import os
import hashlib

def calculate_jar_sha256(jar_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(jar_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"Error reading JAR file {jar_path}: {e}")
        return None

def write_hash_to_file(jar_path, hash_value):
    try:
        # 获取 JAR 包所在的目录
        jar_dir = os.path.dirname(jar_path)
        # 拼接 checksums.sha256 文件的完整路径
        checksum_file_path = os.path.join(jar_dir, 'calculate.sha256')
        # 将哈希值和 JAR 包文件名写入到 checksums.sha256 文件中
        with open(checksum_file_path, 'w') as f:
            f.write(f"{hash_value}  {os.path.basename(jar_path)}\n")
        print("Hash value written to calculate.sha256 successfully.")
    except Exception as e:
        print(f"Error writing hash to calculate.sha256: {e}")

def main():
    # 指定 JAR 包的位置和名称
    jar_path = os.path.join(os.getcwd(), 'target', 'blockchain.jar')

    if not os.path.exists(jar_path):
        print(f"JAR file {jar_path} not found.")
        return

    # 计算 JAR 包的 SHA-256 哈希值
    jar_sha256 = calculate_jar_sha256(jar_path)
    if jar_sha256:
        # 将哈希值写入到 checksums.sha256 文件
        write_hash_to_file(jar_path, jar_sha256)
    print("py ok")

if __name__ == "__main__":
    main()
