# ZeroTrust_AI_Project/analyze_logs.py
import json
from collections import Counter
import os
import sys
from datetime import datetime, timedelta

# Ensure config can be imported to find the log file path
project_root = os.path.abspath(os.path.dirname(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

try:
    from config import LOG_FILE
except ImportError:
    print("Error: Could not import LOG_FILE from config.py. Using default 'logs/activity.log'.")
    LOG_FILE = os.path.join(project_root, 'logs', 'activity.log') # Default fallback

def get_log_summary(log_path=LOG_FILE, time_window_minutes=60):
    """
    Analyzes the JSON log file and returns summary dictionaries.
    """
    summary = {
        'total_events': 0,
        'event_counts': Counter(),
        'failed_logins': Counter(),
        'permission_denials': Counter(),
        'prediction_outcomes': Counter(),
        'errors': []
    }

    if not os.path.exists(log_path):
        summary['errors'].append(f"Log file not found at {log_path}")
        return summary

    now = datetime.now()
    time_threshold = now - timedelta(minutes=time_window_minutes)
    processed_lines = 0

    try:
        with open(log_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                processed_lines += 1
                try:
                    log_entry = json.loads(line.strip())
                    timestamp_str = log_entry.get('asctime')
                    try:
                        timestamp = datetime.strptime(timestamp_str.split(',')[0], '%Y-%m-%d %H:%M:%S')
                    except (ValueError, TypeError, AttributeError):
                         try: # Try ISO format as fallback
                             timestamp = datetime.fromisoformat(timestamp_str)
                         except (ValueError, TypeError, AttributeError):
                             summary['errors'].append(f"Warning: Could not parse timestamp '{timestamp_str}' on line {line_num}.")
                             timestamp = now # Process anyway

                    if timestamp >= time_threshold:
                        summary['total_events'] += 1
                        event_type = log_entry.get('event_type', 'unknown')
                        summary['event_counts'][event_type] += 1

                        # Specific Event Analysis
                        if event_type == 'auth_fail':
                            user = log_entry.get('username_attempted', 'unknown_user')
                            summary['failed_logins'][user] += 1
                        elif event_type == 'authz_fail_role':
                            user = log_entry.get('user_id', 'unknown_user')
                            path = log_entry.get('path', 'unknown_path')
                            summary['permission_denials'][f"User '{user}' -> '{path}'"] += 1
                        elif event_type == 'predict_success':
                            p_class = log_entry.get('predicted_class', 'N/A')
                            summary['prediction_outcomes'][f"Class {p_class}"] += 1
                        elif event_type == 'predict_fail':
                            summary['prediction_outcomes']['Failures'] += 1
                        # Add more elif conditions for other event_types if needed

                except json.JSONDecodeError:
                    summary['errors'].append(f"Warning: Skipping non-JSON line {line_num}")
                except Exception as e:
                     summary['errors'].append(f"Warning: Error processing line {line_num}: {e}")

    except Exception as e:
        summary['errors'].append(f"Error reading log file: {e}")

    # Convert Counters to plain dicts for easier template rendering
    summary['event_counts'] = dict(summary['event_counts'])
    summary['failed_logins'] = dict(summary['failed_logins'])
    summary['permission_denials'] = dict(summary['permission_denials'])
    summary['prediction_outcomes'] = dict(summary['prediction_outcomes'])

    return summary

    
if __name__ == "__main__":
    print("Running standalone log analysis...")
    analysis_results = get_log_summary(time_window_minutes=60)
    # Pretty print the results dictionary
    import pprint
    pprint.pprint(analysis_results)