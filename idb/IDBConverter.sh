# Converts all IDBs in a directory to ESDBs

idb_dir="${1:-./}"

if [ ! -d "venv" ]; then
    python3 -m venv venv
    venv/bin/python3 -m pip install -r requirements.txt
fi

source venv/bin/activate
for file in "$idb_dir"/*.idb; do
    output=${file%.*}.yml
    if [ -f "$output" ]; then
        echo "Removing $output..."
        rm "$output"
    fi
    if [ -f "$file" ]; then
        echo "$file -> $output..."
        (python3 pyidbutil/idbtool.py $file --segs; python3 pyidbutil/idbtool.py $file -n) | python3 IDBCurator.py > ${file%.*}.yml
    fi
done
