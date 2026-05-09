"""
Feature Inferrer - Maps file paths to user-facing features.

Uses folder and file name heuristics to infer what user-facing features
are implemented in each file.
"""

import logging
from typing import List, Set

logger = logging.getLogger(__name__)

# Feature inference mapping based on path and file name keywords
FEATURE_KEYWORDS = {
    "Authentication": {
        "keywords": ["auth", "login", "session", "jwt", "oauth", "credential", "authenticate", "sign"],
        "folders": ["auth", "authentication", "login", "session", "oauth", "jwt"]
    },
    "Payment Processing": {
        "keywords": ["payment", "billing", "checkout", "stripe", "invoice", "transaction", "charge", "cart"],
        "folders": ["payment", "payments", "billing", "checkout", "stripe", "invoicing"]
    },
    "File Upload": {
        "keywords": ["upload", "file", "media", "storage", "s3", "bucket", "attachment"],
        "folders": ["upload", "uploads", "file", "files", "media", "storage", "s3"]
    },
    "API Layer": {
        "keywords": ["api", "rest", "graphql", "endpoint", "route", "controller", "handler"],
        "folders": ["api", "apis", "routes", "endpoints", "controllers", "handlers"]
    },
    "Admin Interface": {
        "keywords": ["admin", "dashboard", "panel", "management", "console", "control"],
        "folders": ["admin", "dashboard", "panel", "management", "console"]
    },
    "Email / Notifications": {
        "keywords": ["email", "mail", "smtp", "notification", "alert", "message", "send"],
        "folders": ["email", "emails", "mail", "notification", "notifications", "messaging"]
    },
    "Search": {
        "keywords": ["search", "index", "elastic", "query", "filter", "find", "lookup"],
        "folders": ["search", "index", "indexing", "elastic", "lucene"]
    },
    "User Management": {
        "keywords": ["user", "profile", "account", "register", "signup", "identity", "permission"],
        "folders": ["user", "users", "profile", "account", "accounts", "identity"]
    },
    "Background Jobs": {
        "keywords": ["webhook", "event", "queue", "worker", "celery", "job", "task", "async"],
        "folders": ["webhook", "webhooks", "queue", "queues", "worker", "workers", "jobs"]
    },
    "Reporting / Analytics": {
        "keywords": ["report", "export", "csv", "pdf", "analytics", "dashboard", "metrics", "stats"],
        "folders": ["report", "reports", "analytics", "export", "reporting"]
    }
}


def infer_features(filepath: str) -> List[str]:
    """
    Infers user-facing features from a file path.
    
    Args:
        filepath: e.g., "payments/api.py", "auth/client.js", "upload_handler.ts"
    
    Returns:
        List of inferred feature names, e.g., ["Payment Processing", "API Layer"]
    """
    if not filepath:
        return []
    
    # Normalize path separators
    filepath = filepath.replace("\\", "/").lower()
    
    # Extract parts
    parts = filepath.split("/")
    filename = parts[-1]
    
    inferred_features: Set[str] = set()
    
    # Check folder names (prioritize folder structure over filename)
    for part in parts[:-1]:  # All folders except the filename
        for feature, keywords_dict in FEATURE_KEYWORDS.items():
            if part in keywords_dict["folders"]:
                inferred_features.add(feature)
                break  # Each part matches at most one feature
            
            # Also check loose keywords in folder names
            for keyword in keywords_dict["keywords"]:
                if keyword in part:
                    inferred_features.add(feature)
                    break
    
    # Check filename (only if no features matched from folders)
    if not inferred_features:
        filename_no_ext = filename.rsplit(".", 1)[0]
        
        for feature, keywords_dict in FEATURE_KEYWORDS.items():
            # Check filename keywords
            for keyword in keywords_dict["keywords"]:
                if keyword in filename_no_ext:
                    inferred_features.add(feature)
                    break
    
    return sorted(list(inferred_features))


def infer_features_from_imports(imports: List[str]) -> List[str]:
    """
    Infers features from a list of imported packages.
    
    Args:
        imports: List of package names, e.g., ["stripe", "requests", "flask"]
    
    Returns:
        List of inferred feature names
    """
    inferred_features: Set[str] = set()
    
    # Map known packages to features
    package_feature_map = {
        "stripe": "Payment Processing",
        "braintree": "Payment Processing",
        "paypal": "Payment Processing",
        "square": "Payment Processing",
        
        "flask": "API Layer",
        "django": "API Layer",
        "fastapi": "API Layer",
        "express": "API Layer",
        "nestjs": "API Layer",
        "spring": "API Layer",
        "springboot": "API Layer",
        
        "boto3": "File Upload",
        "s3": "File Upload",
        "aws-sdk": "File Upload",
        
        "jwt": "Authentication",
        "oauth": "Authentication",
        "passport": "Authentication",
        "pyjwt": "Authentication",
        
        "celery": "Background Jobs",
        "rq": "Background Jobs",
        "bull": "Background Jobs",
        "kue": "Background Jobs",
        
        "elastic": "Search",
        "elasticsearch": "Search",
        "lucene": "Search",
        
        "sendgrid": "Email / Notifications",
        "mailgun": "Email / Notifications",
        "nodemailer": "Email / Notifications",
        "smtplib": "Email / Notifications",
        
        "pandas": "Reporting / Analytics",
        "matplotlib": "Reporting / Analytics",
        "plotly": "Reporting / Analytics",
        "dc.js": "Reporting / Analytics",
    }
    
    for pkg in imports:
        pkg_lower = pkg.lower().replace("-", "").replace("_", "")
        
        # Check direct matches
        for known_pkg, feature in package_feature_map.items():
            if pkg_lower == known_pkg.lower().replace("-", "").replace("_", ""):
                inferred_features.add(feature)
                break
    
    return sorted(list(inferred_features))
