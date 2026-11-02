"""Run the single-process application with validated server configuration."""

import sys

import uvicorn
from pydantic import ValidationError

from app.config import Settings
from app.main import create_app


def main() -> None:
    try:
        settings = Settings()
    except ValidationError:
        sys.exit(
            "Invalid configuration. Check .env against .env.example and README.md."
        )
    uvicorn.run(
        create_app(settings),
        host=str(settings.app_host),
        port=settings.app_port,
        workers=1,
        reload=False,
        proxy_headers=False,
        access_log=False,
    )


if __name__ == "__main__":
    main()
