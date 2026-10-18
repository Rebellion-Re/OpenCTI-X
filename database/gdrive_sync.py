"""
ThreatFusion CTI - Google Drive Storage Mirroring Engine
Synchronizes local Parquet Data Lake tables and JSON-L reports with Google Drive.
"""

import io
import os
import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload
from google.oauth2 import service_account

from config.settings import DATA_DIR, PROCESSED_DATA_DIR, GRAPH_DATA_DIR
from config.logging_config import setup_logger

logger = setup_logger("GDriveSync")

SCOPES: List[str] = ["https://www.googleapis.com/auth/drive"]


class GoogleDriveSync:
    def __init__(
        self,
        service_account_info: Optional[Dict[str, Any]] = None,
        folder_id: Optional[str] = None
    ) -> None:
        self.folder_id = folder_id or os.environ.get("GDRIVE_FOLDER_ID")
        self.service = None

        # Resolve service account from dictionary, environment JSON, or secret file
        info = service_account_info
        if not info and "GCP_SERVICE_ACCOUNT_JSON" in os.environ:
            try:
                info = json.loads(os.environ["GCP_SERVICE_ACCOUNT_JSON"])
            except Exception as e:
                logger.error(f"Failed to parse GCP_SERVICE_ACCOUNT_JSON environment variable: {e}")

        if info:
            try:
                creds = service_account.Credentials.from_service_account_info(info, scopes=SCOPES)
                self.service = build("drive", "v3", credentials=creds, cache_discovery=False)
                logger.info("Google Drive service client authenticated successfully.")
            except Exception as e:
                logger.error(f"Google Drive authentication failed: {e}")
        else:
            logger.warning("No service account credentials provided. GDrive synchronization is offline.")

    def is_connected(self) -> bool:
        return self.service is not None and self.folder_id is not None

    def list_remote_files(self) -> Dict[str, str]:
        """Returns a mapping of remote filename -> file ID in the target folder."""
        if not self.is_connected():
            return {}
        try:
            query = f"'{self.folder_id}' in parents and trashed = false"
            results = self.service.files().list(
                q=query,
                fields="files(id, name, modifiedTime)",
                spaces="drive"
            ).execute()
            files = results.get("files", [])
            return {f["name"]: f["id"] for f in files}
        except Exception as e:
            logger.error(f"Failed to list remote Drive files: {e}")
            return {}

    def upload_file(self, local_path: Path, remote_filename: Optional[str] = None) -> bool:
        """Uploads or updates a local file to the root of the specified Drive folder."""
        if not self.is_connected() or not local_path.exists():
            return False

        filename = remote_filename or local_path.name
        remote_files = self.list_remote_files()
        media = MediaFileUpload(str(local_path), resumable=True)
        try:
            if filename in remote_files:
                file_id = remote_files[filename]
                self.service.files().update(
                    fileId=file_id,
                    media_body=media
                ).execute()
                logger.info(f"Updated remote file on Drive: {filename} ({file_id})")
            else:
                file_metadata = {
                    "name": filename,
                    "parents": [self.folder_id]
                }
                created = self.service.files().create(
                    body=file_metadata,
                    media_body=media,
                    fields="id"
                ).execute()
                logger.info(f"Uploaded new file to Drive: {filename} ({created.get('id')})")
            return True
        except Exception as e:
            logger.error(f"Failed to upload {filename} to Google Drive: {e}")
            return False

    def download_file(self, remote_filename: str, destination_path: Path) -> bool:
        """Downloads a specific file by name from the remote Google Drive folder."""
        if not self.is_connected():
            return False

        remote_files = self.list_remote_files()
        if remote_filename not in remote_files:
            logger.warning(f"File not found on Google Drive: {remote_filename}")
            return False

        file_id = remote_files[remote_filename]
        destination_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            request = self.service.files().get_media(fileId=file_id)
            fh = io.FileIO(str(destination_path), mode="wb")
            downloader = MediaIoBaseDownload(fh, request)
            done = False
            while not done:
                _, done = downloader.next_chunk()
            logger.info(f"Downloaded {remote_filename} from Drive to {destination_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to download {remote_filename} from Google Drive: {e}")
            return False

    def sync_lakehouse_to_drive(self) -> None:
        """Uploads all processed data lake Parquet files and graph tables to Drive."""
        if not self.is_connected():
            return

        targets = list(PROCESSED_DATA_DIR.glob("*.parquet")) + list(GRAPH_DATA_DIR.glob("*.parquet"))
        for target in targets:
            self.upload_file(target)
        logger.info(f"Synced {len(targets)} Parquet lakehouse files to Google Drive.")

    def sync_lakehouse_from_drive(self) -> None:
        """Downloads all remote Parquet files from Drive into the local lakehouse."""
        if not self.is_connected():
            return

        remote_files = self.list_remote_files()
        for filename in remote_files:
            if filename.endswith(".parquet"):
                if "nodes" in filename or "edges" in filename:
                    dest = GRAPH_DATA_DIR / filename
                else:
                    dest = PROCESSED_DATA_DIR / filename
                self.download_file(filename, dest)
