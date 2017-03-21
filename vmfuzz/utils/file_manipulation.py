""" Module handling the file manipulation """
import os
import shutil
import hashlib
import re
import uuid


def compute_md5(file_name, block_size=2**20):
    """
    Compute the md5 of a file

    Args:
        file_name (string): Name of the file
        block_size (int): Size of the block (to compute md5 on large file)
    Returns:
        string: md5 of the file
    """
    f_desc = open(file_name, "rb")
    md5 = hashlib.md5()
    while True:
        data = f_desc.read(block_size)
        if not data:
            break
        md5.update(data)
    f_desc.close()
    return md5.hexdigest()

def create_dir(directory):
    """
    Create the directory if it does not exist

    Args:
        directory (string): dir to create
    """
    if not os.path.exists(directory):
        os.makedirs(directory)

def move_dir(dir_src, dir_dst):
    """
    Move a directory

    Args:
        dir_src (strng): source dir
        dir_dst (string: destination dir
    Note:
        If the destination existed, it is erased
    """
    shutil.rmtree(dir_dst, ignore_errors=True, onerror=None)
    shutil.copytree(dir_src, dir_dst)

def move_generated_inputs(path_src, path_dst, file_format, pattern_src="", pattern_dst=""):
    """
    Move inputs files

    Args:
        path_src (string): source path
        path_dst (string): destination path
        file_format (string): file format of the files
        pattern_src (string): regex used to match files in the source folder
        pattern_dst (string): regex used to match files in the dest folder
    Returns:
        string list: md5 of all files now present in the dest folder
        copied files are named with random name (+ the file format)
        md5 is used to check that each file is uniq in the dest folder
    """
    if not os.path.exists(path_src) or not os.path.exists(path_dst):
        return []
    src_files = [f for f in os.listdir(
        path_src) if os.path.isfile(os.path.join(path_src, f))]
    if pattern_src != "":
        pattern = re.compile(pattern_src)
        src_files = [x for x in src_files if pattern.match(x)]

    dst_files = [f for f in os.listdir(
        path_dst) if os.path.isfile(os.path.join(path_dst, f))]
    if pattern_dst != "":
        pattern = re.compile(pattern_dst)
        dst_files = [x for x in dst_files if pattern.match(x)]

    dst_md5 = [compute_md5(os.path.join(path_dst, x)) for x in dst_files]

    for src_file in src_files:
        md5 = compute_md5(os.path.join(path_src, src_file))
        if md5 not in dst_md5:
            dst_md5.append(md5)
            dst_filename = str(uuid.uuid4()) + file_format
            src = os.path.join(path_src, src_file)
            dst = os.path.join(path_dst, dst_filename)
            shutil.copy(src, dst)
    return dst_md5
