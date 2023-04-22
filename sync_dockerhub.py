import os
import requests

def update_docker_hub_readme(username, repository, api_key, readme_content):
    login_url = "https://hub.docker.com/v2/users/login"
    data = {
        "username": username, "password": api_key
    }
    response = requests.post(login_url, json=data)
    assert response.status_code == 200
    token = response.json()["token"]

    headers = {"Authorization": f"JWT {token}"}
    url = f"https://hub.docker.com/v2/repositories/{username}/{repository}/"
    data = {
        "full_description": readme_content
    }
    response = requests.patch(url, headers=headers, json=data)
    return response.status_code

if __name__ == "__main__":
    api_key = os.getenv("DOCKER_HUB_API_KEY")
    username = "kagamir"
    repository = "crypto-webdav"

    with open("README.md", "r") as f:
        readme_content = f.read()

    status_code = update_docker_hub_readme(username, repository, api_key, readme_content)
    assert status_code == 200, "Sync readme failed."
