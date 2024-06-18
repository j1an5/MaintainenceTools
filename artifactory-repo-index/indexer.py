import argparse
import csv
import requests
import json
import logging
import time
from tqdm import tqdm
from wcwidth import wcswidth
from tabulate import tabulate
from requests.auth import HTTPBasicAuth
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter

# Establishing a log recorder
def setup_logger(scan_result_save, clear_log):
    logger = logging.getLogger("scan_logger")
    logger.setLevel(logging.INFO)
    # 根据 clear_log 参数决定日志文件的写入模式
    mode = 'w' if clear_log == 'True' else 'a'
    fh = logging.FileHandler(scan_result_save, mode=mode)
    fh.setLevel(logging.INFO)
    formatter = logging.Formatter('%(message)s')
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    return logger

# Handling HTTP errors
def handle_http_error(response, msg):
    if response.status_code == 401:
        print("Authentication failed: Please check your username and password.")
    else:
        print(f"HTTP Error: {msg}. Status code: {response.status_code}, Response: {response.text}")
    exit(1)

# Obtain repository information
def get_repository_info(base_url, repo_name, auth):
    url = f"{base_url}/artifactory/api/repositories/{repo_name}"
    response = requests.get(url, auth=auth, timeout=5)
    if not response.ok:
        handle_http_error(response, "Failed to get repository info")
    repo_info = response.json()
    if not repo_info.get('xrayIndex', False):
        print("The repository is not in the Xray - Index Resource")
        exit(1)
    return repo_info

# Obtain file list
def get_file_list(base_url, package_type, repo_name, auth):
    url = f"{base_url}/artifactory/api/storage/{repo_name}?list&deep=1&listFolders=0&mdTimestamps=1"
    response = requests.get(url, auth=auth, timeout=60)
    if not response.ok:
        handle_http_error(response, "Failed to get file list")
    file_list = response.json()
    if 'files' not in file_list or not file_list['files']:
        print("No index files found in the repository.")
        exit(1)
    file_list['files'] = filter_files_by_package_type(file_list['files'], package_type)
    if not file_list['files']:
        print("No index files left after filtering.")
        exit(1)
    return file_list

# Filter files by package type
def filter_files_by_package_type(files, package_type):
    if package_type not in {'conan','docker','gradle','maven','npm'}:
        print(f'No filter rule is specified and may contain invalid files')
        #exit(1)
    filter_rules = {
        # Xray currently supports the following package formats with new formats added regularly.
        # https://jfrog.com/help/r/jfrog-security-documentation/jfrog-xray
        # Alpine
        # Bower
        'cargo': lambda file: not file['uri'].startswith('/.cargo/') and file['uri'].endswith('.crate') or file['uri'].endswith('.tgz') or file['uri'].endswith('.tar.gz'),
        'composer': lambda file: not file['uri'].startswith('/.composer/'),
        'conan': lambda file: not file['uri'].startswith('/.conan/') and file['uri'].endswith('conanmanifest.txt'),
        'conda': lambda file: file['uri'].endswith('.conda') or file['uri'].endswith('.tar.bz2'),
        'debian': lambda file: not file['uri'].startswith('/dists/') and file['uri'].endswith('.deb'),
        'docker': lambda file: not file['uri'].startswith('/.jfrog/repository.catalog') and not file['uri'].endswith('list.manifest.json') and file['uri'].endswith('manifest.json'),
        # Ivy
        'go': lambda file: file['uri'].endswith('.zip'),
        'gradle': lambda file: not (file['uri'].endswith('.module') or file['uri'].endswith('.pom') or file['uri'].endswith('.xml')),
        'huggingfaceml': lambda file: file['uri'].endswith('.jfrog_huggingface_model_info.json'),
        'maven': lambda file: not (file['uri'].endswith('.pom') or file['uri'].endswith('.xml')),
        'nuget': lambda file: not (file['uri'].startswith('/.nuGetV3/')) and  not (file['uri'].startswith('/.nuget/')) and file['uri'].endswith('.nupkg') or file['uri'].endswith('.dll') or file['uri'].endswith('.exe'),
        'npm': lambda file: not file['uri'].startswith('/.npm/'),
        # OCI
        'pypi': lambda file: not file['uri'].startswith('/.pypi/'),
        # SBT
        'rpm': lambda file: file['uri'].endswith('.rpm'),
        # RubyGems
        'terraformbackend': lambda file: file['uri'].endswith('state.latest.json')
    }
    return [file for file in files if filter_rules.get(package_type, lambda f: True)(file)]

# Filter files
def filter_files(file_list, pkg_support_rules):
    for file in file_list['files']:
        file['support'] = any(file['uri'].endswith(ext['extension']) for rule in pkg_support_rules['supported_package_types'] for ext in rule.get('extensions', []))
    return file_list

# Function to retry retrieving scan status
def get_scan_status_with_retry(base_url, repo_name, package_type, file, auth, rclass, logger, max_retries=3, retry_interval=1, timeout=5):
    retry_count = 0
    if rclass == 'remote':
        repo_name += '-cache'
    url = f"{base_url}/xray/api/v1/scan/status/artifact"
    data = {
        "repository_pkg_type": package_type,
        "path": f"{repo_name}{file['uri']}",
        "sha256": file['sha2']
    }
    while retry_count < max_retries:
        try:
            response = requests.post(url, json=data, auth=auth, timeout=timeout)
            response.raise_for_status()
            scan_status = response.json()
            return {"uri": file['uri'], "status": scan_status['status']}
        except requests.exceptions.RequestException as e:
            logger.error(f"Error: {file['uri']}. Retrying {retry_count+1}/{max_retries} after {retry_interval} seconds. Error: {e}")
            time.sleep(retry_interval)
            retry_count += 1
    logger.error(f"Failed to get scan status for {file['uri']}. Setting status to ERROR.")
    return {"uri": file['uri'], "status": "ERROR"}

# Update status and save results
def update_status_and_save(filtered_files, base_url, repo_name, package_type, auth, rclass, logger, print_lines, format, threads, scan_result_save):
    def scan_file(file):
        if file['support']:
            scan_status = get_scan_status_with_retry(base_url, repo_name, package_type, file, auth, rclass, logger)
            file['status'] = scan_status['status']
        return file

    total_files = sum(1 for file in filtered_files['files'] if file['support'])
    progress_bar = tqdm(total=total_files, desc="Scanning Files")
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(scan_file, file) for file in filtered_files['files'] if file['support']]
        for future in as_completed(futures):
            future.result()  # Wait for task to complete
            progress_bar.update(1)

    progress_bar.close()
    end_time = time.time()

    # Format and save scan results
    save_scan_results(filtered_files, repo_name, total_files, start_time, end_time, logger, print_lines, format, scan_result_save)

# Accumulate scan statuses
def accumulate_scan_statuses(scan_statuses):
    return Counter(scan_statuses)

# Save scan results
def save_scan_results(filtered_files, repo_name, total_files, start_time, end_time, logger, print_lines, format, scan_result_save):
    table_data = [[file['uri'], file['support'], file.get('status', 'N/A')] for file in filtered_files['files']]
    max_len = [max(wcswidth(str(row[i])) for row in table_data) for i in range(len(table_data[0]))]
    formatted_data = [[str(cell).ljust(max_len[i]) for i, cell in enumerate(row)] for row in table_data]
    formatted_data.sort(key=lambda row: (row[1], row[2], row[0]))

    status_counts = accumulate_scan_statuses([file.get('status', 'N/A') for file in filtered_files['files']])
    logger.info(f"[{repo_name}] - Potential files: {total_files}, Scan Status Counts: {status_counts}")
    print(f"[Repo ] - [{repo_name}] - Potential files: {total_files}, Scan Status Counts: {status_counts}")
    logger.info(f"[Sum  ] - Total time taken: {end_time - start_time:.2f} seconds")
    print(f"[Sum  ] - Total time taken: {end_time - start_time:.2f} seconds")

    if len(formatted_data) > print_lines:
        print(tabulate(formatted_data[:print_lines], headers=["File Path", "support", "Scan Status"], tablefmt="grid"))
        print(f"\n[Warn ] ... (Additional rows are logged in the file: {scan_result_save} )")
    else:
        print(tabulate(formatted_data, headers=["File Path", "support", "Scan Status"], tablefmt="grid"))

    if format == "csv":
        with open(scan_result_save, 'w', newline='') as csv_file:
            csv_writer = csv.writer(csv_file)
            csv_writer.writerow(["File Path", "support", "Scan Status"])
            for row in formatted_data:
                csv_writer.writerow(row)
    elif format == "json":
        with open(scan_result_save, 'w') as json_file:
            json.dump(filtered_files, json_file, indent=4)
    elif format == "table":
        logger.info(tabulate(formatted_data, headers=["File Path", "support", "Scan Status"], tablefmt="grid"))
    else:
        print("[Warn ] Unkonw type for format, set format to table")
        logger.info(tabulate(formatted_data, headers=["File Path", "support", "Scan Status"], tablefmt="grid"))

        


def main():
    default_base_url = "http://localhost:8082"
    default_pkg_support = "Xray_pkg_support.json"
    default_username = "admin"
    default_password = "password"
    default_scan_result_save = "scan_details.file"
    default_print_lines = 10
    default_clear_log = "True"
    default_format = "table"
    default_threads = 50

    parser = argparse.ArgumentParser(description="Artifactory Repository for scan")
    parser.add_argument('reponame', type=str, help='The name of the repository')
    parser.add_argument('--base_url', type=str, default=default_base_url, help=f'The base URL for the Artifactory instance (default: {default_base_url})')
    parser.add_argument('--pkg_support', type=str, default=default_pkg_support, help=f'The package support rules file (default: {default_pkg_support})')
    parser.add_argument('--username', type=str, default=default_username, help='Artifactory username')
    parser.add_argument('--password', type=str, default=default_password, help='Artifactory password')
    parser.add_argument('--scan_result_save', type=str, default=default_scan_result_save, help=f'File to save scan results (default: {default_scan_result_save})')
    parser.add_argument('--print_lines', type=int, default=default_print_lines, help=f'Number of lines to print in the console (default: {default_print_lines})')
    parser.add_argument('--format', type=str, default=default_format, help=f'Format of data: table | json | csv (default: {default_format})')
    parser.add_argument('--clear_log', type=str, default=default_clear_log, help=f'Empty the log (default: {default_clear_log})')
    parser.add_argument('--threads', type=int, default=default_threads, help=f'Number of threads for concurrent API calls (default: {default_threads})')

    args = parser.parse_args()

    repo_name = args.reponame
    base_url = args.base_url
    pkg_support_file = args.pkg_support
    username = args.username
    password = args.password
    scan_result_save = args.scan_result_save
    print_lines = args.print_lines
    clear_log = args.clear_log
    format = args.format
    threads = args.threads

    auth = HTTPBasicAuth(username, password)

    # 设置日志记录器
    logger = setup_logger(scan_result_save, clear_log)

    with open(pkg_support_file, 'r') as f:
        pkg_support_rules = json.load(f)

    repo_info = get_repository_info(base_url, repo_name, auth)
    package_type = repo_info['packageType']
    rclass = repo_info['rclass']

    # 获取文件列表并过滤
    file_list = get_file_list(base_url, package_type, repo_name, auth)
    filtered_files = filter_files(file_list, pkg_support_rules)
    
    # 更新扫描状态并保存结果
    update_status_and_save(filtered_files, base_url, repo_name, package_type, auth, rclass, logger, print_lines, format, threads, scan_result_save)

if __name__ == "__main__":
    main()
