import hashlib
import os
import sys
import zipfile

def calculate_sha256(file_path):
    """计算文件的SHA-256哈希值"""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            # 分块读取以处理大文件
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"计算哈希值时出错: {e}")
        return None

def get_expected_hash(sha_file_path):
    """从SHA256文件中提取预期的哈希值"""
    try:
        with open(sha_file_path, 'r') as f:
            first_line = f.readline().strip()
            # 格式应为: <hash> <空格或*><文件名>
            parts = first_line.split()
            if len(parts) >= 1:
                return parts[0]
            else:
                print("SHA256文件格式不正确")
                return None
    except Exception as e:
        print(f"读取SHA256文件时出错: {e}")
        return None

def main():
    if len(sys.argv) != 3:
        print("用法: python 文件名.py zip名 sha256文件名")
        sys.exit(1)

    zip_file_path = os.path.abspath(sys.argv[1])
    sha_file_path = os.path.abspath(sys.argv[2])

    # 假设要验证的文件在zip文件内，这里简单假设zip内有一个blockchain.jar文件
    try:
        with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
            # 解压blockchain.jar到当前目录
            jar_file_path = 'blockchain.jar'
            zip_ref.extract('blockchain.jar')
    except Exception as e:
        print(f"解压zip文件时出错: {e}")
        sys.exit(1)

    # 计算实际哈希值
    actual_hash = calculate_sha256(jar_file_path)
    if actual_hash is None:
        sys.exit(1)

    # 获取预期哈希值
    expected_hash = get_expected_hash(sha_file_path)
    if expected_hash is None:
        sys.exit(1)

    # 比较哈希值
    if actual_hash == expected_hash:
        print("哈希值验证通过...")
        sys.exit(0)
    else:
        print("错误: 哈希值不匹配!")
        print(f"计算值: {actual_hash}")
        print(f"预期值: {expected_hash}")
        sys.exit(1)

if __name__ == "__main__":
    main()