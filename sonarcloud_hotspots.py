#!/usr/bin/env python3
"""
SonarCloud Security Hotspots Exporter

This script exports all security hotspots for a project in SonarCloud.io
"""
import argparse
import csv
import json
import os
import sys
import requests
from typing import Dict, Any, List, Optional


class SonarCloudHotspotExporter:
    def __init__(self, token: Optional[str] = None):
        """Initialize the exporter with SonarCloud API token"""
        self.token = token or os.environ.get("SONARCLOUD_TOKEN")
        if not self.token:
            raise ValueError("SonarCloud API token is required. Set SONARCLOUD_TOKEN env variable or pass via --token")
        
        self.base_url = "https://sonarcloud.io/api"
        self.session = requests.Session()
        self.session.auth = (self.token, "")
        
    def list_projects(self, organization: str) -> List[Dict[str, Any]]:
        """List all projects in an organization"""
        all_projects = []
        page = 1
        page_size = 500
        
        while True:
            url = f"{self.base_url}/projects/search"
            params = {
                "organization": organization,
                "p": page,
                "ps": page_size
            }
            
            try:
                response = self.session.get(url, params=params)
                response.raise_for_status()
                data = response.json()
                
                projects = data.get("components", [])
                all_projects.extend(projects)
                
                # Check if there are more pages
                total = data.get("paging", {}).get("total", 0)
                if page * page_size >= total:
                    break
                    
                page += 1
                
            except requests.exceptions.HTTPError as e:
                print(f"API Error: {e}")
                print(f"Response content: {response.text}")
                return []
                
        return all_projects

    def get_hotspots(self, organization: str, project_key: str) -> List[Dict[str, Any]]:
        """Get all security hotspots for a project"""
        all_hotspots = []
        statuses = ["TO_REVIEW", "REVIEWED"]
        
        # Fetch hotspots for each status separately
        for status in statuses:
            page = 1
            page_size = 500
            
            print(f"Fetching hotspots with status: {status}")
            
            while True:
                url = f"{self.base_url}/hotspots/search"
                params = {
                    "organization": organization,
                    "projectKey": project_key,
                    "p": page,
                    "ps": page_size,
                    "status": status
                }
                
                response = self.session.get(url, params=params)
                try:
                    response.raise_for_status()
                except requests.exceptions.HTTPError as e:
                    print(f"API Error: {e}")
                    print(f"Response content: {response.text}")
                    raise
                    
                data = response.json()
                
                hotspots = data.get("hotspots", [])
                all_hotspots.extend(hotspots)
                
                # Check if there are more pages
                total = data.get("paging", {}).get("total", 0)
                if page * page_size >= total:
                    break
                    
                page += 1
        
        return all_hotspots
    
    def enrich_hotspot_data(self, organization: str, hotspots: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enrich hotspot data with additional details"""
        enriched_hotspots = []
        
        for hotspot in hotspots:
            hotspot_key = hotspot.get("key")
            if not hotspot_key:
                continue
                
            url = f"{self.base_url}/hotspots/show"
            params = {
                "organization": organization,
                "hotspot": hotspot_key
            }
            
            response = self.session.get(url, params=params)
            if response.status_code == 200:
                detailed_data = response.json()
                # Merge the detailed data with the basic hotspot data
                enriched_hotspot = {**hotspot, **detailed_data}
                enriched_hotspots.append(enriched_hotspot)
            else:
                # If we can't get detailed info, use the basic info
                enriched_hotspots.append(hotspot)
                
        return enriched_hotspots

    def export_hotspots(self, organization: str, project: str, project_key: str, 
                       output_format: str = "json", output_file: Optional[str] = None,
                       status_filter: Optional[str] = None, 
                       category_filter: Optional[str] = None,
                       severity_filter: Optional[str] = None,
                       summary: bool = False) -> None:
        """Export security hotspots to the specified format"""
        print(f"Fetching security hotspots for {project} ({project_key})...")
        
        # Get all hotspots for the project
        hotspots = self.get_hotspots(organization, project_key)
        
        # Enrich hotspot data with additional details
        enriched_hotspots = self.enrich_hotspot_data(organization, hotspots)
        
        # Apply filters if specified
        filtered_hotspots = enriched_hotspots
        
        if status_filter:
            filtered_hotspots = [h for h in filtered_hotspots if h.get("status") == status_filter]
            print(f"Filtered to {len(filtered_hotspots)} hotspots with status: {status_filter}")
            
        if category_filter:
            filtered_hotspots = [h for h in filtered_hotspots if h.get("securityCategory") == category_filter]
            print(f"Filtered to {len(filtered_hotspots)} hotspots with category: {category_filter}")
            
        if severity_filter:
            filtered_hotspots = [h for h in filtered_hotspots if h.get("vulnerabilityProbability") == severity_filter]
            print(f"Filtered to {len(filtered_hotspots)} hotspots with severity: {severity_filter}")
        
        # Display summary if requested
        if summary and filtered_hotspots:
            self._display_summary(filtered_hotspots)
        
        # Prepare the output
        if output_format == "json":
            self._export_to_json(filtered_hotspots, output_file)
        elif output_format == "csv":
            self._export_to_csv(filtered_hotspots, output_file)
        else:
            print(f"Unsupported output format: {output_format}")
    
    def _display_summary(self, hotspots: List[Dict[str, Any]]) -> None:
        """Display a summary of the hotspots"""
        print("\n=== SECURITY HOTSPOTS SUMMARY ===")
        print(f"Total hotspots: {len(hotspots)}")
        
        # Group by file
        files = {}
        for hotspot in hotspots:
            file_path = hotspot.get("component", {}).get("path", "unknown")
            files[file_path] = files.get(file_path, 0) + 1
        
        print("\nTop affected files:")
        for file_path, count in sorted(files.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {file_path}: {count} issues")
        
        # Display a few example hotspots
        if hotspots:
            print("\nExample hotspots:")
            for i, hotspot in enumerate(hotspots[:3], 1):
                print(f"  {i}. {hotspot.get('message', 'No message')}")
                print(f"     File: {hotspot.get('component', {}).get('path', 'unknown')}")
                print(f"     Line: {hotspot.get('line', 'unknown')}")
                print(f"     Category: {hotspot.get('securityCategory', 'unknown')}, Severity: {hotspot.get('vulnerabilityProbability', 'unknown')}")
                print()
    
    def _export_to_json(self, hotspots: List[Dict[str, Any]], output_file: Optional[str] = None) -> None:
        """Export hotspots to JSON format"""
        output = json.dumps(hotspots, indent=2)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
            print(f"Exported {len(hotspots)} hotspots to {output_file}")
        else:
            print(output)
    
    def _export_to_csv(self, hotspots: List[Dict[str, Any]], output_file: Optional[str] = None) -> None:
        """Export hotspots to CSV format"""
        if not hotspots:
            print("No hotspots found.")
            return
        
        # Define CSV fields based on the first hotspot's keys
        # Use the most important fields for security analysis
        fieldnames = [
            "key", "component", "project", "securityCategory", "vulnerabilityProbability", 
            "status", "line", "message", "author", "creationDate", "updateDate", 
            "rule", "textRange.startLine", "textRange.endLine", "ruleDescriptionContextKey"
        ]
        
        # Flatten nested structures for CSV output
        flattened_hotspots = []
        for hotspot in hotspots:
            flat_hotspot = {}
            for key in fieldnames:
                if "." in key:
                    # Handle nested fields like "textRange.startLine"
                    parts = key.split(".")
                    value = hotspot
                    for part in parts:
                        if isinstance(value, dict) and part in value:
                            value = value[part]
                        else:
                            value = ""
                            break
                    flat_hotspot[key] = value
                else:
                    flat_hotspot[key] = hotspot.get(key, "")
            flattened_hotspots.append(flat_hotspot)
        
        if output_file:
            with open(output_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(flattened_hotspots)
            print(f"Exported {len(hotspots)} hotspots to {output_file}")
        else:
            writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(flattened_hotspots)


def main():
    parser = argparse.ArgumentParser(description="SonarCloud Security Hotspots Exporter")
    parser.add_argument("--organization", "-o", required=True, help="SonarCloud organization key")
    parser.add_argument("--project", "-p", help="Project name")
    parser.add_argument("--key", "-k", help="Project key in SonarCloud")
    parser.add_argument("--token", "-t", help="SonarCloud API token (or set SONARCLOUD_TOKEN env variable)")
    parser.add_argument("--format", "-f", choices=["json", "csv"], default="json", help="Output format (default: json)")
    parser.add_argument("--output", help="Output file (default: stdout)")
    parser.add_argument("--list-projects", "-l", action="store_true", help="List available projects in the organization")
    parser.add_argument("--list-categories", action="store_true", help="List available security categories in the results")
    parser.add_argument("--status", choices=["TO_REVIEW", "REVIEWED"], help="Filter by status")
    parser.add_argument("--category", help="Filter by security category (e.g., auth, xss)")
    parser.add_argument("--severity", choices=["HIGH", "MEDIUM", "LOW"], help="Filter by vulnerability probability/severity")
    parser.add_argument("--summary", "-s", action="store_true", help="Display a summary of the results")
    
    args = parser.parse_args()
    
    try:
        exporter = SonarCloudHotspotExporter(args.token)
        
        # List projects mode
        if args.list_projects:
            print(f"Listing projects for organization: {args.organization}")
            projects = exporter.list_projects(args.organization)
            
            if not projects:
                print("No projects found or unable to access projects.")
                return
                
            print(f"\nFound {len(projects)} projects:")
            print(f"{'Project Name':<50} {'Project Key':<50}")
            print(f"{'-' * 50} {'-' * 50}")
            
            for project in sorted(projects, key=lambda p: p.get("name", "")):
                print(f"{project.get('name', 'N/A'):<50} {project.get('key', 'N/A'):<50}")
                
            return
        
        # List categories mode (requires a project)
        if args.list_categories:
            if not args.project or not args.key:
                print("Error: --project and --key are required for listing categories")
                print("Tip: Use --list-projects to see available projects and keys")
                sys.exit(1)
                
            print(f"Fetching security hotspots to analyze categories...")
            hotspots = exporter.get_hotspots(args.organization, args.key)
            
            if not hotspots:
                print("No hotspots found in the project.")
                return
                
            # Extract and count categories
            categories = {}
            severities = {}
            
            for hotspot in hotspots:
                # Count by category
                category = hotspot.get("securityCategory", "unknown")
                categories[category] = categories.get(category, 0) + 1
                
                # Count by severity
                severity = hotspot.get("vulnerabilityProbability", "unknown")
                severities[severity] = severities.get(severity, 0) + 1
            
            print(f"\nFound {len(hotspots)} total hotspots with the following categories:")
            print(f"{'Category':<20} {'Count':<10}")
            print(f"{'-' * 20} {'-' * 10}")
            
            for category, count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
                print(f"{category:<20} {count:<10}")
                
            print(f"\nBreakdown by severity:")
            print(f"{'Severity':<20} {'Count':<10}")
            print(f"{'-' * 20} {'-' * 10}")
            
            for severity, count in sorted(severities.items(), key=lambda x: x[1], reverse=True):
                print(f"{severity:<20} {count:<10}")
                
            return
            
        # Export hotspots mode
        if not args.project or not args.key:
            print("Error: --project and --key are required for exporting hotspots")
            print("Tip: Use --list-projects to see available projects and keys")
            sys.exit(1)
            
        print(f"Using:")
        print(f"  Organization: {args.organization}")
        print(f"  Project: {args.project}")
        print(f"  Project Key: {args.key}")
        
        # Apply filters if specified
        filters = []
        if args.status:
            filters.append(f"status={args.status}")
        if args.category:
            filters.append(f"category={args.category}")
        if args.severity:
            filters.append(f"severity={args.severity}")
            
        if filters:
            print(f"  Filters: {', '.join(filters)}")
        
        exporter.export_hotspots(
            args.organization, 
            args.project, 
            args.key, 
            args.format, 
            args.output,
            args.status,
            args.category,
            args.severity,
            args.summary
        )
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()