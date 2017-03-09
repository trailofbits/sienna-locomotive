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
        file_name (string): Name of the fil
        block_size (int): Size of the block (to compute md5 on large file)
    Return:
    md5 of the file (string)
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


def move_generated_inputs(path_src, path_dst, file_format, pattern_src="", pattern_dst=""):
    """
    Move inputs files
    Args:
        path_src (string): source path 
        path_dst (string): destination path 
        file_format (string): file format of the files
        pattern_in (string): regex used to match files in the source folder
        pattern_out (string): regex used to match files in the dest folder
    Returns:
        md5 of all files now present in the dest folder
        copied files are named with random name (+ the file format)
        md5 is used to check that each file is uniq in the dest folder
    """
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

    for x in src_files:
        md5 = compute_md5(os.path.join(path_src, x))
        if(md5 not in dst_md5):
            dst_md5.append(md5)
            dst_filename = str(uuid.uuid4()) + file_format
            src = os.path.join(path_src, x)
            dst = os.path.join(path_dst, dst_filename)
            shutil.copy(src, dst)
    return dst_md5
