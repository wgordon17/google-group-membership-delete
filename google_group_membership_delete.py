import argparse
import json
import os
import secrets
import sys
import webbrowser

import flask

import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery

# This variable specifies the name of a file that contains the OAuth 2.0
# information for this application, including its client_id and client_secret.
CLIENT_SECRETS_FILE = "client_secret.json"
CLIENT_CREDENTIALS_FILE = "client_credentials.json"

# This OAuth 2.0 access scope allows for full read/write access to the
# authenticated user's account and requires requests to use an SSL connection.
SCOPES = [
    'https://www.googleapis.com/auth/cloud-identity.groups',
]

app = flask.Flask(__name__)
# See https://flask.palletsprojects.com/quickstart/#sessions.
app.secret_key = secrets.token_urlsafe(64)


@app.route('/authorize')
def authorize():
    # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow steps.
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES
    )

    # The URI created here must exactly match one of the authorized redirect URIs
    # for the OAuth 2.0 client, which you configured in the API Console. If this
    # value doesn't match an authorized URI, you will get a 'redirect_uri_mismatch'
    # error.
    flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

    authorization_url, state = flow.authorization_url(
        # Enable offline access so that you can refresh an access token without
        # re-prompting the user for permission. Recommended for web server apps.
        access_type='offline',
        # Enable incremental authorization. Recommended as a best practice.
        include_granted_scopes='true'
    )

    # Store the state so the callback can verify the auth server response.
    flask.session['state'] = state

    return flask.redirect(authorization_url)


@app.route('/oauth2callback')
def oauth2callback():
    # Specify the state when creating the flow in the callback so that it can
    # be verified in the authorization server response.
    state = flask.session['state']

    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, state=state
    )
    flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

    # Use the authorization server's response to fetch the OAuth 2.0 tokens.
    authorization_response = flask.request.url
    flow.fetch_token(authorization_response=authorization_response)

    # Store credentials in a file
    credentials_to_file(flow.credentials)

    return "Successfully authenticated. You may close this window and restart the script."


def credentials_to_file(credentials):
    with open(CLIENT_CREDENTIALS_FILE, 'w') as f:
        f.write(json.dumps({
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes
        }))


def credentials_from_file(filename=CLIENT_CREDENTIALS_FILE):
    with open(filename, 'r') as f:
        return json.loads(f.read())


def request_credentials_from_flask():
    # When running locally, disable OAuthlib's HTTPs verification.
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'
    webbrowser.open('http://localhost:8080/authorize')
    # If the file doesn't exist, run Flask server to request user credentials
    app.run('localhost', 8080)


def get_group(service, list_email):
    request = service.groups().lookup()
    request.uri += '&groupKey.id=' + list_email
    response = request.execute()
    return response


def get_membership(service, group_id, membership_email):
    request = service.groups().memberships().lookup(parent=group_id)
    request.uri += '&memberKey.id=' + membership_email
    response = request.execute()
    return response


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--list-email", help="Group mailing list email address (<name>@<domain-name>)")
    parser.add_argument("-m", "--membership-email", help="Email address of member subscribed to Group mailing list (<name>@<domain-name>)")
    parser.add_argument("-d", "--delete-membership", help="Flag to delete the membership", action='store_true')
    args = parser.parse_args(argv[1:])

    try:
        credentials = credentials_from_file()
    except (json.JSONDecodeError, FileNotFoundError):
        try:
            os.remove(CLIENT_CREDENTIALS_FILE)
        except FileNotFoundError:
            pass
        request_credentials_from_flask()
    else:
        # Parse credentials
        credentials = google.oauth2.credentials.Credentials(**credentials)
        service = googleapiclient.discovery.build('cloudidentity', 'v1', credentials=credentials)

        group = get_group(service, args.list_email)

        if group_id := group.get('name'):
            membership = get_membership(service, group_id, args.membership_email)

            if membership_id := membership.get('name'):
                if args.delete_membership:
                    request = service.groups().memberships().delete(name=membership_id)
                    response = request.execute()
                    print(f'Deleted? {response}')
                else:
                    print(membership_id)

        # Save credentials back to file in case access token was refreshed.
        credentials_to_file(credentials)


if __name__ == '__main__':
    main(sys.argv)
