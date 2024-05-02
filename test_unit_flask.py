import pytest
from flask import url_for
from flask_app import app, classifier_model  # Import your Flask app configuration here
import pandas as pd
from unittest.mock import patch

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_benign(client):
    # Mocking the classifier model's predict method
    with patch.object(classifier_model, 'predict', return_value=[0]) as mock_predict:
        response = client.get('/')
        mock_predict.assert_called_once()  # Ensure predict was called
        assert response.status_code == 200
        print(response.data)
        # assert b"Hello, welcome to your feed" in response.data

def test_malicious(client):
    with patch.object(classifier_model, 'predict', return_value=[1,2,3,4,5,6]) as mock_predict:
        response = client.get('/')
        mock_predict.assert_called_once()
        assert response.status_code == 302  # Check for redirection
        follow_redirect = client.get(response.location)
        assert b"Malicious request detected, redirecting to FIDO2 Gateway" in follow_redirect.data
