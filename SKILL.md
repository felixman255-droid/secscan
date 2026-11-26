---
name: secscan
description: "Varredura de segurança local em um projeto: segredos commitados (gitleaks), CVEs em dependências (osv-scanner) e SAST (semgrep) em um único comando, com relatório unificado por severidade. Usar quando o usuário pedir para escanear ou auditar a segurança de um projeto, procurar chaves/tokens vazados no código, checar vulnerabilidades em dependências, rodar SAST, ou invocar /secscan. Triggers: secscan, escanear segurança, varrer projeto, segredo vazado, chave exposta, CVE, vulnerabilidade em dependência, SAST, auditoria de segurança, security scan."
agent_created: true
---

# secscan — varredura de segurança local

Executa três camadas de defesa sobre o código do próprio usuário e entrega um relatório unificado.
Todas as ferramentas são gratuitas, portáteis e rodam offline após a primeira execução.

Este arquivo segue o formato de skill (frontmatter com `name` e `description`) lido por Claude
Code e WorkBuddy. Agentes que usam a convenção `AGENTS.md` encontram instruções equivalentes
em `AGENTS.md`, na raiz deste diretório. O núcleo é o `secscan.py`, que é um CLI comum e não
depende de agente nenhum.

## Antes de rodar: checar a instalação

O diretório desta skill deve conter `secscan.py`, `bin/` e `.venv/`. Verificar:

```bash
ls <diretório-da-skill>/bin/gitleaks* <diretório-da-skill>/bin/osv-scanner* <diretório-da-skill>/.venv
```

Se `bin/` ou `.venv/` não existirem, rodar o instalador uma vez:

```powershell
powershell -ExecutionPolicy Bypass -File "<diretório-da-skill>\install.ps1"
```

```bash
bash "<diretório-da-skill>/install.sh"
```

## Como rodar

Windows (PowerShell), caminho preferido:

```powershell
& "<diretório-da-skill>\secscan.cmd" "<PROJETO>" --out "<diretório-da-skill>\security-report"
```

Git Bash, Linux ou macOS:

```bash
"<diretório-da-skill>/secscan.sh" "<PROJETO>" --out "<diretório-da-skill>/security-report"
```

Sempre passar `--out` apontando para dentro do diretório da skill, para não sujar a pasta do
projeto do usuário com relatórios. Sempre entre aspas: caminhos no Windows costumam ter espaços.

### Flags

| Flag | Efeito |
|---|---|
| `--history` | gitleaks varre todo o histórico do git — acha segredo commitado e depois apagado |
| `--semgrep-config p/...` | troca o ruleset (padrão `p/default`) |
| `--no-secrets` / `--no-deps` / `--no-sast` | pula uma camada |
| `--fail-on critica\|alta\|media\|baixa\|nunca` | severidade que faz sair com código 1 (padrão `alta`) |

Usar `--history` quando o alvo for repositório git — é o cenário mais perigoso, porque um
segredo removido do código continua válido no provedor.

## Depois de rodar

1. Ler o `relatorio.md` gerado (o caminho aparece no fim da saída do comando).
2. Resumir para o usuário por severidade, destacando CRÍTICA e ALTA.
3. Para cada achado relevante, informar arquivo, linha e o que fazer.
4. Sinalizar explicitamente quais achados são provavelmente falso positivo, e por quê.

Não colar o relatório inteiro na resposta. O usuário quer saber o que corrigir primeiro.

## Interpretação

**CRÍTICA** — segredo exposto ou CVSS ≥ 9.0. Corrigir hoje.
Segredo commitado deve ser **revogado**, não apenas removido do código: o valor já vazou.

**ALTA** — CVSS 7.0–8.9 ou padrão de código explorável. Corrigir na sprint.

**MÉDIA** — CVSS 4.0–6.9 ou padrão suspeito dependente de contexto.

O relatório aponta *onde*, não *se é explorável naquele caso*. Antes de tratar como urgente,
verificar se o dado realmente chega do usuário até o ponto apontado. Um `eval()` que só lê
config local não tem o peso de um `eval()` numa rota HTTP.

## Limites a comunicar ao usuário

- SAST não prova exploração — aponta padrão de risco, e falso positivo é normal.
- A camada de dependências só funciona se houver lockfile (`package-lock.json`, `poetry.lock`,
  `go.sum`, `composer.lock`). Sem lockfile, o osv-scanner aparece como "pulado" e o projeto
  fica cego justamente na camada que mais rende.
- Isso não substitui pentest: falha de lógica de negócio (usuário A acessando dado do usuário B)
  só um humano com contexto do domínio encontra.

## Armadilhas de API (não regredir)

- gitleaks ≥ 8.19 **removeu** o subcomando `detect`. Usar `git` ou `dir`, com o alvo como
  **argumento posicional** — `--source` gera `unknown flag`.
- `osv-scanner` expõe `groups[].max_severity` como **nota CVSS numérica** ("8.7"), não rótulo.
  Mapear por faixa: ≥9 CRÍTICA, ≥7 ALTA, ≥4 MÉDIA, >0 BAIXA.
- `semgrep` marca `confidence: LOW` em regras de segredo e SQLi por heurística. **Não** rebaixar
  severidade por isso — rebaixar esconde chave de API exposta.
- `gitleaks dir` não respeita `.gitignore`. O `secscan.py` já gera um TOML temporário com
  `[extend] useDefault = true` e `[[allowlists]] paths` para ignorar `node_modules`, `.venv`,
  `dist`, `build`, `target`, `vendor`.
- Console do Windows não está em UTF-8: a saída do terminal usa rótulos sem acento
  (`CRITICA`), e o `relatorio.md` mantém a acentuação correta.

## Aviso de dados sensíveis

O `gitleaks.json` dentro da pasta do relatório contém o valor do segredo encontrado.
Não commitar `security-report/` e apagar o relatório após revisar em máquina compartilhada.
