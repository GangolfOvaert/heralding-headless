# Copyright (C) 2017 Johnny Vestergaard <jkv@unixcluster.dk>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import csv
import logging
import json
import requests

from heralding.reporting.base_logger import BaseLogger

logger = logging.getLogger(__name__)

# --- CONFIGURATION ---
# Change this to the IP/URL of your second server
REMOTE_SERVER_URL = "http://127.0.0.1:5000/api/logs" 
# Optional: Add a token if your receiver requires it
REMOTE_AUTH_TOKEN = "your-secret-token" 
# ---------------------

class FileLogger(BaseLogger):

  def __init__(self, session_csv_logfile, sessions_json_logfile, auth_logfile):
    super().__init__()
    # We override the file logger to ignore local files and send data remotely.
    logger.info('Remote Logger initialized. Sending data to %s', REMOTE_SERVER_URL)

  def setup_csv_files(self, filename, field_names):
    # Not used in headless remote mode
    pass

  def loggerStopped(self):
    # No file handles to close
    pass

  def _send_remote(self, log_type, data):
    """Helper to send data to the remote server"""
    try:
        payload = {
            "log_type": log_type,
            "data": data
        }
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {REMOTE_AUTH_TOKEN}"
        }
        # Use a short timeout to prevent the honeypot from hanging if the log server is down
        requests.post(REMOTE_SERVER_URL, json=payload, headers=headers, timeout=3.0)
    except Exception as e:
        # Log to stderr/syslog so we know something is wrong, but don't crash
        logger.error(f"Failed to send log to remote server: {e}")

  def handle_auth_log(self, data):
    # for now this logger only handles authentication attempts where we are able
    # to log both username and password
    if 'username' in data and 'password' in data:
        self._send_remote("auth", data)

  def handle_session_log(self, data):
    if data['session_ended']:
        self._send_remote("session", data)
