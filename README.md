# secscan

Varredura de segurança em um comando, para o **seu próprio** código.
Três camadas — segredos, dependências e código-fonte — num único relatório.

```bash
./secscan.sh /caminho/do/seu-projeto
```

```
  gitleaks       ok (1.0s)
  osv-scanner    ok (4.1s)
  semgrep        ok (10.6s)

  CRITICA     6
  ALTA       14
  MEDIA      17

  * Segredo exposto: aws-access-token
    app.py:5
```

## O que roda

| Camada | Ferramenta | Pega o quê |
|---|---|---|
| Segredos | [gitleaks](https://github.com/gitleaks/gitleaks) 8.30 | token, chave de API, senha commitada |
| Dependências | [osv-scanner](https://github.com/google/osv-scanner) 2.7 | CVE em biblioteca de terceiros, com CVSS real |
| Código (SAST) | [semgrep](https://semgrep.dev) 1.187 | injeção SQL, `eval`, `shell=True`, cripto fraca, XSS |

Todas gratuitas. Depois da primeira execução, rodam offline.

## Instalação

**Windows:**

```powershell
powershell -ExecutionPolicy Bypass -File install.ps1
```

**Linux / macOS:**

```bash
bash install.sh
```

Cria `bin/` (gitleaks + osv-scanner portáteis) e `.venv/` (semgrep isolado). Nada é instalado
no sistema — só arquivos nesta pasta.

## Uso

```bash
./secscan.sh                          # pasta atual
./secscan.sh ../meu-projeto           # pasta específica
./secscan.sh ../meu-projeto --history # inclui histórico do git
```

No PowerShell: `& ".\secscan.cmd" "..\meu-projeto"`

### Opções

| Flag | Efeito |
|---|---|
| `--out DIR` | pasta de saída (padrão `security-report`) |
| `--history` | gitleaks varre todo o histórico do git — mais lento, mas acha segredo que foi apagado |
| `--semgrep-config p/...` | troca o ruleset (padrão `p/default`) |
| `--no-secrets` `--no-deps` `--no-sast` | pula uma das camadas |
| `--fail-on critica\|alta\|media\|baixa\|nunca` | severidade que faz sair com código 1 (padrão `alta`) |

O código de saída serve para CI: `0` passou, `1` achou algo na severidade limite.

## Saída

Console resumido + `security-report/<timestamp>/` com:

- `relatorio.md` — tabela completa por severidade, com instruções de correção
- `gitleaks.json`, `osv.json`, `semgrep.json` — saída bruta de cada ferramenta

## Como interpretar

**CRÍTICA** — corrija hoje. Segredo exposto ou CVE com CVSS ≥ 9.0.
Segredo é sempre crítico porque não basta remover do código: se foi commitado, considere vazado
e **revogue** a credencial.

**ALTA** — corrija nesta sprint. CVSS 7.0–8.9, ou padrão de código explorável.

**MÉDIA** — corrija no ciclo. CVSS 4.0–6.9, ou padrão suspeito que depende de contexto.

O relatório aponta *onde*, não *se é explorável no seu caso*. Um `eval()` num script que só lê
config local não é o mesmo que um `eval()` numa rota HTTP. Confirme o caminho do dado antes de
tratar como urgente.

## Limites

- **SAST não prova exploração.** Aponta padrão de risco. Falso positivo é normal — calibre as
  regras com o tempo.
- **A camada de dependências precisa de lockfile** (`package-lock.json`, `poetry.lock`,
  `go.sum`, `composer.lock`...). Sem ele, o osv-scanner fica cego — e é justamente a camada
  que mais rende na prática.
- **Não substitui pentest.** Isso pega o que já é conhecido e automatizável. Falha de lógica de
  negócio (usuário A acessando pedido do usuário B) só um humano com contexto encontra.

## Segurança dos dados

O `gitleaks.json` contém o valor do segredo encontrado. `security-report/` está no
`.gitignore` — não commite. Apague o relatório depois de revisar em máquina compartilhada.

## Uso autorizado

Ferramenta para auditar código que é seu ou que você tem autorização para testar.
Testar sistema de terceiros sem permissão escrita é crime no Brasil (Lei 12.737/2012)
e na maioria das jurisdições.

## Licença

MIT — veja [LICENSE](LICENSE).
