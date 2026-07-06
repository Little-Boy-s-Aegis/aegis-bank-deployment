# Aegis Database Backup Script for Windows

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$deployDir = Resolve-Path "${scriptDir}/.."
$backupDir = "${deployDir}/backups"

if (!(Test-Path $backupDir)) {
    New-Item -ItemType Directory -Force -Path $backupDir
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFile = "${backupDir}/aegis_backup_${timestamp}.sql"

Write-Host "=================================================="
Write-Host "Starting PostgreSQL backup: $(Get-Date)"
Write-Host "Target file: $backupFile"

# Run pg_dump inside docker container and stream to backup file
docker compose -f "${deployDir}/docker-compose.yml" exec -T postgres pg_dump -U postgres -d aegis > $backupFile

if ($LASTEXITCODE -eq 0) {
    Write-Host "Backup completed successfully!"
    
    # Compress the file using PowerShell Compress-Archive
    Compress-Archive -Path $backupFile -DestinationPath "${backupFile}.zip" -Force
    Remove-Item $backupFile
    Write-Host "Compressed file: ${backupFile}.zip"
    
    # Retention policy: Deleting backups older than 7 days
    Write-Host "Applying retention policy (deleting backups older than 7 days)..."
    Get-ChildItem -Path $backupDir -Filter "aegis_backup_*.sql.zip" | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-7) } | Remove-Item
    Write-Host "Cleanup completed."
} else {
    Write-Warning "ERROR: Backup failed!"
    if (Test-Path $backupFile) { Remove-Item $backupFile }
    exit 1
}
Write-Host "=================================================="
