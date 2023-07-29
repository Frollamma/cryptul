echo "Open pyproject.toml and update the version number."
read -n1 -r -p "Press any key to continue..."
rm -rf dist
python3 -m build
python3 -m twine upload --repository pypi dist/*
