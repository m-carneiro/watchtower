package domain

import "time"

type IOCType string

const (
	IPAddress IOCType = "ip"
	Domain    IOCType = "domain"
	FileHash  IOCType = "file_hash"
	URL       IOCType = "url"
	Package   IOCType = "package"
)

type IOC struct {
	Value        string    // A URL maliciosa (ex: http://malware.com/bin) ou nome do pacote
	Type         IOCType   // O tipo (url, package, ip, etc)
	Source       string    // De onde veio (URLhaus, OSV, etc)
	ThreatType   string    // Classificação da fonte (ex: malware_download)
	Tags         []string  // Tags originais (ex: exe, elf, mips)
	Version      string    // Versão afetada (apenas para pacotes, vazio para outros tipos)
	FirstSeen    time.Time // Quando a fonte viu isso pela primeira vez
	DateIngested time.Time // Quando NÓS processamos isso
}

/*
 - Definir o que é um IOC.
 - Definir o que é uma fonte.
*/
