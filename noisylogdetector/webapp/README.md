# Log Quality Analyzer - Web Application

A Flask-based web application for analyzing log files to detect noisy logging, sensitive data exposure, and incorrect severity usage.

## � Version

| Component | Version |
|-----------|---------|
| **Web Application** | 1.0.0 |
| **Flask** | 2.3.3 |
| **Werkzeug** | 2.3.7 |
| **PyYAML** | 6.0.1 |
| **Jinja2** | 3.1.2 |
| **Python** | 3.6+ |

> **Note:** This is the web application (Flask UI + REST API) version of the Log Quality Analyzer.
> It does **not** include CLI or GoogleTest integration — see the root `README.md` for those features.

---

## ���� Quick Start

### Prerequisites
- Python 3.6 or higher
- pip package manager

### Installation & Setup

> ⚠️ **Important:** You must run `setup.py` first before starting the application. Skipping this step may result in missing dependencies, directories, or configuration files.

1. **Navigate to the webapp directory:**
   ```bash
   cd noisylogdetector/webapp
   ```

2. **Run the setup script (required — first time only):**
   ```bash
   python3 setup.py
   ```
   This will:
   - Verify Python 3.6+ is installed
   - Install required dependencies from `requirements.txt`
   - Create necessary directories (`uploads/`, `static/`, `templates/`)
   - Validate all required files are in place

3. **Once setup completes successfully, start the web application:**
   ```bash
   python3 app.py
   ```

4. **Open your browser and go to:**
   ```
   http://localhost:5000
   ```

## ��� Features

### Web Interface
- **File Upload**: browse to upload log files
- **Real-time Analysis**: Instant results displayed in the browser
- **Interactive Results**: Click-to-copy log entries, visual highlighting
- **Downloadable Reports**: Generate and download HTML reports
- **Rules Editor**: Web-based YAML configuration editor
- **Analysis History**: View and manage previous analyses

### API Endpoints
- `POST /api/analyze` - Upload and analyze log files
- `GET /api/rules` - Retrieve current rules configuration
- `PUT /api/rules` - Update rules configuration
- `GET /api/history` - Get analysis history

## ��� Project Structure

```
webapp/
├── app.py                 # Main Flask application
├── log_analyzer.py        # Core analysis logic
├── setup.py              # Setup and installation script
├── requirements.txt       # Python dependencies
├── rules.yml             # Analysis rules configuration
├── analysis_history.db   # SQLite database for history
├── uploads/              # Temporary file uploads
├── templates/            # HTML templates
│   ├── base.html
│   ├── index.html        # Main upload page
│   ├── results.html      # Analysis results
│   ├── rules.html        # Rules configuration
│   └── history.html      # Analysis history
└── static/               # CSS, JavaScript, and assets
    ├── css/
    │   └── style.css
    └── js/
        └── app.js
```

## � Python Scripts

### `app.py` — Main Flask Application

The entry point of the web application. Responsibilities:

- Initialises the Flask app and configures file upload limits (16 MB max) and allowed extensions (`.log`, `.txt`).
- Manages an **SQLite database** (`analysis_history.db`) with `init_db()` to persist analysis history across sessions.
- Defines all **route handlers** for the web UI:
  - `GET /` — Renders the main upload page (`index.html`)
  - `POST /analyze` — Accepts an uploaded log file, calls `log_analyzer.py`, saves results to the DB, and renders `results.html`
  - `GET /history` — Renders the analysis history page
  - `GET /rules` / `POST /rules` — Renders and handles the rules editor page
- Exposes **REST API endpoints** under `/api/`:
  - `POST /api/analyze` — Upload and analyze a log file (JSON response)
  - `GET /api/rules` — Return current `rules.yml` as JSON
  - `PUT /api/rules` — Update `rules.yml` from JSON body
  - `GET /api/history` — Return past analysis records as JSON
- Handles `RequestEntityTooLarge` errors gracefully when uploaded files exceed the size limit.

**Run directly to start the server (after running `setup.py` first):**
```bash
python3 app.py
# Server starts at http://localhost:5000
```

---

### `log_analyzer.py` — Core Analysis Logic

A self-contained module adapted from `noisylogdetector.py` for use by the Flask application. It has **no web dependencies** and can be imported or tested independently. Responsibilities:

- `load_rules(path)` — Loads and validates `rules.yml`, raising clear exceptions on missing keys or malformed YAML.
- `starts_with_date_and_timestamp(line)` — Detects log lines via regex, supporting multiple timestamp formats:
  - ISO 8601 (`2025-12-17T12:16:47.917Z`)
  - Time-only (`12:16:47.916231`)
  - Date + time (`2024-11-11 04:31:14`)
  - WPE-specific (`251217-12:16:58.240119`)
  - Month-name format (`Nov 11 04:31:14`)
- `analyze_log_file(log_file, rules)` — Iterates over log lines and returns three lists: noisy logs, sensitive logs, and severity violations.
- `generate_html_report(noisy, sensitive, severity, output_path)` — Writes a standalone HTML report file with all findings.

---

### `setup.py` — Setup & Installation Script

A one-time setup utility that prepares the environment before running the application for the first time. It runs the following steps in order:

| Step | Function | What it does |
|------|----------|-------------|
| 1 | `check_python_version()` | Verifies Python 3.6+ is in use; exits if not |
| 2 | `create_directories()` | Creates `uploads/`, `static/css/`, `static/js/`, `templates/` if missing |
| 3 | `check_files()` | Confirms all required files (`app.py`, `log_analyzer.py`, templates, static assets) are present |
| 4 | `copy_rules_file()` | Copies `../rules.yml` into the `webapp/` directory if not already present |
| 5 | `install_dependencies()` | Runs `pip install -r requirements.txt` to install all Python packages |

**Run once before first launch:**
```bash
cd webapp
python3 setup.py
```

---

## ���� Configuration

### Rules Configuration (rules.yml)

The application uses a YAML configuration file to define analysis rules:

```yaml
# Patterns to detect sensitive information
sensitive_patterns:
  - '(?i)\btoken\s*[:=]\s*[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,}'
  - '(?i)\b(api[_-]?key|apikey)\s*[:=]\s*[A-Za-z0-9]{20,}'
  - '(?i)\b(password|passwd|pwd)\s*[:=]\s*\S{6,}'

# Log levels considered noisy
noisy_log_levels:
  - DEBUG
  - TRACE
  - INFO

# Keywords indicating failure
failure_keywords:
  - failed
  - error
  - exception
  - timeout

# Required log levels for failure messages
required_severity_on_failure:
  - ERROR
```

### Application Configuration

You can modify settings in `app.py`:

```python
# File upload limits
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

# Allowed file extensions
ALLOWED_EXTENSIONS = {'txt', 'log'}

# Database location
DATABASE = 'analysis_history.db'
```

## ��� Analysis Categories

### 1. Noisy Logs
Detects excessive logging at verbose levels:
- **DEBUG** - Development debugging information
- **TRACE** - Detailed execution traces  
- **INFO** - General informational messages

### 2. Sensitive Data Exposure
Identifies potentially sensitive information:
- JWT tokens and API keys
- Passwords and authentication data
- IP addresses and URLs
- Private keys and certificates
- MAC addresses

### 3. Severity Violations
Finds failure conditions logged at incorrect levels:
- Failure keywords at non-ERROR levels
- Missing required severity for critical events

## ��� API Usage

### Analyze Log File
```bash
curl -X POST -F "file=@logfile.log" http://localhost:5000/api/analyze
```

### Get Rules Configuration
```bash
curl http://localhost:5000/api/rules
```

### Update Rules Configuration
```bash
curl -X PUT -H "Content-Type: application/json" \
     -d @new_rules.json http://localhost:5000/api/rules
```

### Get Analysis History
```bash
curl http://localhost:5000/api/history
```

## ���️ Development

### Running in Development Mode
```bash
export FLASK_ENV=development
python3 app.py
```

### Testing the API
Use the included test scripts or tools like Postman to test API endpoints.

### Custom Modifications
- **Templates**: Modify HTML templates in the `templates/` directory
- **Styling**: Update CSS in `static/css/style.css`
- **Functionality**: Extend JavaScript in `static/js/app.js`
- **Analysis Logic**: Modify `log_analyzer.py` for custom analysis rules

## ��� Security Considerations

- **File Upload Limits**: Set appropriate file size limits
- **Input Validation**: Validate all user inputs
- **Sensitive Data**: Log entries with sensitive data are automatically redacted
- **HTTPS**: Use HTTPS in production environments
- **Authentication**: Consider adding user authentication for production use

## ��� Performance Tips

- **File Size**: Keep uploaded files under 16MB for optimal performance
- **Database**: Regular cleanup of old analysis history
- **Memory**: Monitor memory usage for large log files
- **Concurrent Users**: Consider using a production WSGI server like Gunicorn

## ��� Troubleshooting

### Common Issues

1. **"Rules file not found"**
   - Ensure `rules.yml` exists in the webapp directory
   - Run the setup script to copy rules file

2. **"Permission denied"**
   - Check file permissions on uploads directory
   - Ensure Python has write access to the application directory

3. **"File too large"**
   - Files over 16MB are rejected by default
   - Modify `MAX_CONTENT_LENGTH` if needed

4. **"Database errors"**
   - Delete `analysis_history.db` to reset the database
   - Check if SQLite is properly installed

### Debug Mode
Run with debug mode for detailed error information:
```bash
export FLASK_DEBUG=1
python3 app.py
```

## ��� License

This project is licensed under the same terms as the original Log Quality Analyzer.

## ��� Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## ��� Support

For issues and questions:
- Check the troubleshooting section above
- Review the original project documentation
- Create an issue in the project repository

