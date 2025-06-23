#!/bin/bash

usage()
{
	script=$(basename $0)
	echo -e "Usage:"
	echo -e "\t$script [version]"
	echo -e "\teg:$script pt-1.1.rc0"
	exit
}

if [ $# -ne 1 ]
then
	usage
fi

mkdir release 2> /dev/null || true
mkdir release/submodules 2> /dev/null || true

script_dir=$(dirname $(readlink -f $0))
proj_top=$(readlink -f "${script_dir}/../")
old_version=$(grep 'define DRV_VERSION' $proj_top/src/mce_version.h  | awk '{gsub("\"","",$3) ;print $3}')
new_version=$1
git_commit=$(git rev-parse --short HEAD)

if [ $old_version = $new_version ]
then
	echo "new version ${new_version} is same as old version ${old_version}"
	exit
fi

echo "old version : ${old_version}"
echo "new version : ${new_version}"

sed  -i "s/.*DRV_VERSION.*/#define DRV_VERSION \"${new_version}\"/g" $proj_top/src/mce_version.h
sed  -i "s/.*GIT_COMMIT.*/#define GIT_COMMIT \"${git_commit}\"/g" $proj_top/src/mce_version.h

cd $proj_top
git commit -am "release: $new_version $git_commit"
git tag -d $new_version 2>/dev/null || true
git tag $new_version

#remove
rm ./release/submodules/* -rf 2>/dev/null || true
prefix_new="mcepf-${new_version}"
out_file="./release/mcepf-${new_version}.tar.gz"
git archive --format=tar.gz --prefix="${prefix_new}/" -o "$out_file" HEAD ${proj_top}
git submodule foreach --recursive '
    SUBMODULE_PATH=$path
    SUBMODULE_NAME=$(basename $SUBMODULE_PATH)
    SUBMODULE_ARCHIVE="$SUBMODULE_NAME.tar.gz"
    # 为子模块创建归档文件
    git archive --prefix=$SUBMODULE_PATH/ --format=tar.gz --output=$SUBMODULE_ARCHIVE HEAD
    # 将子模块归档文件添加到主项目归档文件中
    # tar -rf $out_file $SUBMODULE_ARCHIVE
    # 删除子模块的临时归档文件
    #rm $SUBMODULE_ARCHIVE
    #tar -xvf $SUBMODULE_ARCHIVE -C ./release/${prefix_new}
    mv $SUBMODULE_ARCHIVE ../../release/submodules/
'
# setup new tar, not good
tar -xvf ${out_file} -C ./release/ > /dev/null 2>&1
rm ${out_file} -rf > /dev/null 2>&1
new_file="mcepf-${new_version}"
out_file="mcepf-${new_version}.tar.gz"
tar -xvf ./release/submodules/* -C ./release/${new_file} > /dev/null 2>&1
cd release
tar -cvf ${out_file} ${new_file} > /dev/null 2>&1
rm ${new_file} -rf > /dev/null 2 >&1
cd ..

