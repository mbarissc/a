import click
from commands import (
    init,
    import_nessus_cmd,
    # Hosts
    list_hosts, add_host, update_host, delete_host,
    # Vulns
    list_vulns, update_vuln, delete_vuln,
    # Users
    add_user, list_users, update_user, delete_user,
    # Assign/Action/History
    assign_vuln, my_vulns, set_action, history_cmd,
    # Reports
    summary, export_csv, generate_report
)

@click.group()
def cli():
    pass

# DB
cli.add_command(init)

# Import
cli.add_command(import_nessus_cmd, name="import-nessus")

# Hosts
cli.add_command(list_hosts)
cli.add_command(add_host)
cli.add_command(update_host)
cli.add_command(delete_host)

# Vulns
cli.add_command(list_vulns)
cli.add_command(update_vuln)  # mesaj veriyor, manuel status yok
cli.add_command(delete_vuln)

# Users
cli.add_command(add_user)
cli.add_command(list_users)
cli.add_command(update_user)
cli.add_command(delete_user)

# Assign/Action/History
cli.add_command(assign_vuln)
cli.add_command(my_vulns)
cli.add_command(set_action)
cli.add_command(history_cmd, name="history")

# Reports
cli.add_command(summary)
cli.add_command(export_csv)
cli.add_command(generate_report)

if __name__ == "__main__":
    cli()
