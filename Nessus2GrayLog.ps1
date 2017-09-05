# Definition des différents répertoires de travail
$cRepNessus= "[répertoire où sont les rapports Nessus]"
$PathGraylog = "C:\Program Files\Graylog\collector-sidecar\generated"

# Récupération de la liste des fichiers présents dans le répertoire NESSUS
$repertoireNessus = @()
$repertoireNessus = Get-ChildItem -Path $cRepNessus -File *.nessus

clear

# Parcours le répertoire NESSUS
foreach ($fichiersNessus in $repertoireNessus) {

	# Recuperation de la date du scan a partir du nom du fichier
	$DateScan = ""
	$RegexFormatDate1 = "[0-9]{2}-[0-9]{1,2}-[0-9]{4}"
	$DateScan = "$repertoireNessus" -match $RegexFormatDate1

	# Si la Regex du format de date est vrai
	if ($DateScan) {

		$RegexAnnee = "[0-9]{4}"
		$RegexMois = "Scan_PROD_DPT_[0-9]{2}_[0-9]{2}-([0-9]{2})"
		$RegexJours = "Scan_PROD_DPT_[0-9]{1,2}_([0-9]{1,2})"
		
		$DateScanAnnee = "$repertoireNessus" -match $RegexAnnee
		$DateScanAnnee = $Matches.Values
		
		$DateScanMois = "$repertoireNessus" -match $RegexMois
		$DateScanMois = $Matches[1]
		
		$DateScanJours = "$repertoireNessus" -match $RegexJours
		$DateScanJours = $Matches[1]
		
		$DateScan = "$DateScanAnnee-$DateScanMois-$DateScanJours" + "09:00:00,980"
	}

	# Sinon (format de date v2)
	else {

		$RegexFormatDate1 = "[0-9]{4}-[0-9]{2}-[0-9]{1,2}"
		$DateScan = "$repertoireNessus" -match $RegexFormatDate1
		$DateScan = $Matches.Values + "09:00:00,980"
	}
	
	echo "[ii]`tTraitement du fichier $fichiersNessus"
	
	Try {
			echo "[ii]`tParsing du XML..."
			[xml]$xmldata	= get-content -Path $cRepNessus$fichiersNessus
			$ressources		= $xmldata.NessusClientData_v2.Report.ReportHost
			echo "[OK]`tParsing ok !"
		}
		Catch {
			throw( "[!!]`tErreur lors du parsing du XML - $Error[0]")
		}
		
		$report	= @()
		
		# Parcours du fichier XML
		foreach ($res in $ressources) {
	
			foreach ($res2 in $res.ReportItem) {
			$Severity = $res2.severity
			
				# Récupération des vulnrabilités superieure à 2 (medium - high - critique)
				if ($Severity -ge 2) {
				
					$TableauScanNessus = new-object PSObject
				
					$TableauScanNessus | add-member -type NoteProperty -Name NomScan -Value $res.ParentNode.name -Force
					$TableauScanNessus | add-member -type NoteProperty -Name AdresseIP -Value $res.Name	-Force
					$TableauScanNessus | add-member -type NoteProperty -Name NumeroPort -Value $res2.port	-Force
					$TableauScanNessus | add-member -type NoteProperty -Name Severity -Value $res2.risk_factor	-Force
					$TableauScanNessus | add-member -type NoteProperty -Name PluginNameNessus -Value $res2.pluginName	-Force
					$TableauScanNessus | add-member -type NoteProperty -Name DescriptionVuln -Value $res2.synopsis	-Force
					$TableauScanNessus | add-member -type NoteProperty -Name NumeroCVE -Value $res2.cve	-Force
					$TableauScanNessus | add-member -type NoteProperty -Name MSFT -Value $res2.msft	-Force
					
					# Ajout des données dans le tableau
					$report += $TableauScanNessus	
				}
			}
		}
		
		Try {
			# On renomme le fichier PushToGrayLog puis on le supprime
			Rename-Item -Path "$PathGraylog\PushToGrayLog.txt" "$PathGraylog\PushToGrayLog_OLD.txt"
			Start-Sleep -Seconds 3
			Remove-Item -Path "$PathGraylog\PushToGrayLog_OLD.txt" -Force
		}
		Catch {
			echo "[ii]`tPas de fichier PushToGrayLog.txt"
		}
		
		$CompteurLignes = 0
		$CompteurLignes2 = 0
		
		New-Item -Type File -Path "$PathGraylog\PushToGrayLog.txt" -Force
		
		foreach ($rep in $report) {
			
			# Récupération du contenu du tableau
			$NomScan = $rep.NomScan
			$AdresseIP = $rep.AdresseIP
			$NumeroPort = $rep.NumeroPort
			$Severity = $rep.Severity
			$PluginNameNessus = $rep.PluginNameNessus
			$DescriptionVuln = $rep.DescriptionVuln
			$NumeroCVE = $rep.NumeroCVE
			$MSFT = $rep.MSFT
			
			# Récupération des CVE si > 2
			if ($NumeroCVE.Count -ge 2) {
				$NumeroCVE = $NumeroCVE.SyncRoot[1]
			}
			
			# Si pas de CVE
			if ([string]::IsNullOrWhiteSpace($NumeroCVE)) {
				$NumeroCVE = "N/A"
			}
			
			# Si pas de MSFT
			if ([string]::IsNullOrWhiteSpace($MSFT)) {
				$MSFT = "N/A"
			}
			
			# Ecriture des données dans le fichier
			$ContenuFichier = "$NomScan;$DateScan;$AdresseIP;$NumeroPort;$Severity;$NumeroCVE;$MSFT;$PluginNameNessus;$DescriptionVuln"
			
			Start-Sleep -s 1.5
			$ContenuFichier | Out-File "$PathGraylog\PushToGrayLog.txt" -Encoding UTF8 -Append -Force

			$CompteurLignes++
		}
		
		echo "[ii]`tEcriture de $CompteurLignes lignes"
		
		# Déplacement du fichier Nessus
		echo "[ii]`tDéplacement du fichier Nessus"
		Move-Item -Path $cRepNessus$fichiersNessus -Destination "[répertoire archive pour les rapports Nessus traités]"
		
		# Pause de 10 secondes afin d'assurer l'envoi des données dans GrayLog
		echo "[ii]`tPause du processus pendant 10 secondes"
		Start-Sleep -s 10
}
