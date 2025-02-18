import pytest
import requests

@pytest.fixture
def base_url():
    return 'https://api.example.com'

def test_get_user(base_url):
    response = requests.get(f'{base_url}/users/1')
    assert response.status_code == 200
    assert response.json()['name'] == 'John Doe'

def test_create_user(base_url):
    user_data = {"name": "Jane Doe"}
    response = requests.post(f'{base_url}/users', json=user_data)
    assert response.status_code == 201
    assert response.json()['name'] == 'Jane Doe'



@pytest.fixture
def headers():
    return {
        "Authorization": "Bearer TOKEN",
        "Content-Type": "application/json"
    }


API_URL = "https://api.example.com/"

@pytest.mark.parametrize("endpoint", ["/resource", "/other-resource", "/another-resource"])
# Can also parameterize multiple arguments by providing a list of tuples:
#                       ("endpoint, expected_status", [
#       ("/resource", 200),
#       ("/nonexistent", 404),
#       ("/another-resource", 200)
# ])
def test_api_with_auth_header(endpoint, expected_status):
    # Define headers, including Authorization
    headers = {
        "Authorization": "Bearer TOKEN",
        "Content-Type": "application/json",
        "Custom-Header": "CustomValue"
    }
    
    # Make the GET request with headers
    response = requests.get(f"{API_URL}{endpoint}", headers=headers)
    
    assert response.status_code == 200
    # assert response.status_code == expected_status


# mock api response

def fetch_data(api_url):
    response = requests.get(api_url)
    response.raise_for_status() # Raise an error if the status code is 4xx or 5xx
    return response.json()

# mocking requests.get with monkeypatch
def test_fetch_data_success(monkeypatch):
    def mock_get(*args, **kwargs):
        class MockResponse:
            status_code = 200
            def json(self):
                return {"key": "value"}
        return MockResponse()
    
    monkeypatch.setattr("requests.get", mock_get)
    response = fetch_data("url.com")
    assert response == {"key": "value"}

# mocking requests.post with monkeypatch
def test_submit_data(monkeypatch):
    url = "url.com/api"
    test_data = {"key": "value"}
    mock_response_data = {"status": "success"}
    
    def mock_post(*args, **kwargs):
        class MockResponse:
            status_code = 200
            def json(self):
                return mock_response_data
        return MockResponse()
    
    monkeypatch.setattr(requests, "post", mock_post)
    response = submit_data(url, test_data)
    assert response == mock_response_data

# mocking with unittest.mock import patch
from unittest.mock import patch
from requests.models import Response
def test_fetch_data_success_with_um():
    # version 1
    with patch('request.get') as mock_get:
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {"key": "value"}
        response = fetch_data("example.com/api")
        assert response == {"key": "value"}
    
    # version 2
    # sample json data to be returned by the mock
    mock_json_data = {"key": "value"}
    
    # Define a mock response function
    def mock_response(*args, **kwargs):
        mock_resp = Response()
        mock_resp.status_code = 200
        mock_resp._content = b'{"key": "value"}'
        return mock_resp
    
    # Use patch to mock requests.get with mock response
    with patch('requests.get', side_effect=mock_response):
        result = fetch_data('example.com/api/resource')
        assert result == mock_json_data

# Test function for failure
def test_fetch_data_failure_with_um():
    def mock_response(*args, **kwargs):
        mock_resp = Response()
        mock_resp.status_code = 404
        return mock_resp
    with patch('requests.get', side_effect=mock_response):
        with pytest.raises(requests.exceptions.HTTPError):
            fetch_data('example.com/api/resource')


# mock POST request

def submit_data(url, data):
    response = requests.post(url, json=data)
    response.raise_for_status()
    return response.json()


def test_submit_data():
    url = "example.com/api/endpoint"
    test_data = {"key": "value"}
    
    mock_response_data = {"status": "success"}
    
    with patch("requests.post") as mock_post:
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = mock_response_data
        
        response = submit_data(url, test_data)
        
        # Verify the mock was called with the correct parameters
        mock_post.assert_called_once_with(url, json=test_data)
        
        assert response == mock_response_data


            
    
# SECURITY TESTING

BASE_URL = 'https://example.com/api'
AUTH_TOKEN = "token"

@pytest.fixture
def headers():
    return {
        "Authorization": f"Bearer {AUTH_TOKEN}",
        "Content-Type": "application/json"
    }


def test_authentication_required():
    """Test accessing a protected endpoint without authentication."""
    response = requests.get(f"{BASE_URL}/protected-endpoint")
    assert response.status_code == 401, "Endpoint should require authentication."

def test_authorization():
    """Test authorization with a valid token but insufficient permissions."""
    # Assuming this token belongs to a user with restricted token
    restricted_token = "restricted user token"
    headers = {"Authorization": f"Bearer {restricted_token}"}
    response = requests.get(f"{BASE_URL}/admin-endpoint", headers=headers)
    assert response.status_code == 403, "User without admin privileges should not access this endpoint."

@pytest.mark.parametrize("malicious_input", ["DROP TABLE users;", "<script>alert(1);</script>"])
def test_sql_injection(headers, malicious_input):
    """Test SQL injection by sending malicious input."""
    response = requests.post(f"{BASE_URL}/search", json={"query": malicious_input}, headers=headers)
    assert response.status_code == 400 or response.status_code == 200, "API should handle malicious input safely."
    assert "error" not in response.text.lower(), "SQL injection attempt should not cause a server error."

def test_rate_limiting(headers):
    """Send multiple requests in a short period to test rate limiting."""
    for _ in range(20):
        response = requests.get(f"{BASE_URL}/rate-limited-endpoint", headers=headers)
        if response.status_code == 429:
            assert response.status_code == 429, "API should enforce rate limiting."
            break
        else:
            pytest.fail("Rate limiting was not triggered.")

def test_data_exposure(headers):
    """Verify sensitive information is not exposed in API response."""
    response = requests.get(f"{BASE_URL}/user-info", headers=headers)
    sensitive_data = ["password", "credit card"]
    for field in sensitive_data:
        assert field not in response.text, f"Sensitive field {field} found in response!"
        



"""threading, concurrently"""

from concurrent.futures import ThreadPoolExecutor, as_completed

def test_api_endpoint(url, expected_status):
    response = requests.get(url)
    assert response.status_code == expected_status
    return response.status_code

# Define multiple API test cases 
api_tests = [
    {"url": "https://jsonplaceholder.typicode.com/posts", "expected_status": 200},
    {"url": "https://jsonplaceholder.typicode.com/comments", "expected_status": 200},
    {"url": "https://jsonplaceholder.typicode.com/albums", "expected_status": 200},
]

# Run tests concurrently using ThreadPoolExecutor
def run_api_tests_concurrently(api_tests):
    with ThreadPoolExecutor(max_workers=5) as executor:
        # Submit each test function to the thread pool
        futures = [
            executor.submit(test_api_endpoint, test["url"], test["expected_status"])
            for test in api_tests
        ]
    
    
    # Wait for all futures to complete and collect results
    for future in as_completed(futures):
        try:
            result = future.result() # This will raise an exception if a test fail
            print(f"Test passed with status code {result}")
        except AssertionError as e: # Catch exceptions to avoid terminating all tests if one test fails.
            print(f"Test failed: {e}")

# Run the concurrent test suite
if __name__ == '__main__':
    run_api_tests_concurrently(api_tests)


"""
Alternative: Using pytest-xdis
pip install pytest-xdist
pytest -n 5  # Runs tests on 5 parallel workers
the pytest-xdist plugin can parallelize tests across multiple CPU cores. It is a great option for large projects, as it requires little modification to codebase.
pytest-xdist for larger pytest suites
"""

# Max Threads=R×T
# R (requests per second) and the average response time is T (in seconds)


# Test response time using threading
import requests
from concurrent.futures import ThreadPoolExecutor
import time

# Define API endpoint and headers (replace with your values)
url = "https://jsonplaceholder.typicode.com/posts"
headers = {"Authorization": "Bearer YOUR_TOKEN"}

# Function to measure response time
def get_response_time():
    start = time.time()
    response = requests.get(url, headers=headers)
    end = time.time()
    return end - start, response.status_code

# Test function to determine safe thread count
def test_threading(thread_count):
    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        times = list(executor.map(lambda _: get_response_time()[0], range(thread_count)))
        avg_time = sum(times) / len(times)
        print(f"Threads: {thread_count}, Avg response time: {avg_time}")

# Try different thread counts
for threads in [5, 10, 15, 20]:
    test_threading(threads)
