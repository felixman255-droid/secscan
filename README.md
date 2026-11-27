# secscan

Varredura de segurança em um comando, para o **seu próprio** código.
Três camadas — segredos, dependências e código-fonte — num único relatório.

```bash
./secscan.sh /caminho/do/seu-projeto
```

```
  gitleaks       ok (1.0s)
  osv-scanner    ok (4.3s)
  semgrep        ok (12.4s)

  CRITICA     6
  ALTA       14
  MEDIA      18

  * Segredo exposto: aws-access-token
    app.py:5
```

## O que roda

| Camada | Ferramenta | Pega o quê |
|---|---|---|
| Segredos | [gitleaks](https://github.com/gitleaks/gitleaks) 8.30.1 | token, chave de API, senha commitada |
| Dependências | [osv-scanner](https://github.com/google/osv-scanner) 2.7.1 | CVE em biblioteca de terceiros, com nota CVSS |
| Código (SAST) | [semgrep](https://semgrep.dev) 1.187 | injeção SQL, `eval`, `shell=True`, cripto fraca, XSS |

Todas gratuitas. Depois da primeira execução, rodam offline.

As versões são fixas de propósito: o `secscan.py` depende do formato JSON de cada ferramenta.
Trocar de versão exige revalidar o parsing com os testes.

## Compatibilidade com agentes

O núcleo (`secscan.py`) é um CLI comum — roda sozinho, sem agente nenhum, e é o que faz o
trabalho de verdade.

Para usar **como instrução de agente**, o repositório traz os dois formatos que existem hoje:

| Arquivo | Formato | Agentes |
|---|---|---|
| `SKILL.md` | skill com frontmatter (`name` + `description`) | Claude Code, WorkBuddy, e qualquer agente que leia `SKILL.md` |
| `AGENTS.md` | instruções em Markdown puro | Codex, Cursor, Jules, Amp, Zed e demais leitores de `AGENTS.md` |

O `SKILL.md` serve para Claude Code e WorkBuddy **sem alteração** — o formato é o mesmo. Campos
extras no frontmatter são ignorados por quem não os conhece, então nada quebra.

Instalar como skill (Claude Code):

```bash
git clone https://github.com/felixman255-droid/secscan.git ~/.claude/skills/secscan
```

Por projeto, em vez de global: clonar em `.claude/skills/secscan` na raiz do repositório.
Depois rodar o instalador uma vez dentro da pasta clonada.

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
| `--history` | gitleaks varre todo o histórico do git — acha segredo que foi apagado |
| `--baseline ARQ` | arquivo de achados aceitos (padrão `<alvo>/.secscanignore`) |
| `--write-baseline` | grava o baseline com os achados atuais e encerra |
| `--semgrep-config p/...` | troca o ruleset; aceita lista separada por vírgula |
| `--no-stack-rules` | não adiciona os rulesets da stack detectada |
| `--reveal-secrets` | não redigir segredos no JSON (necessário para revogar credencial) |
| `--keep N` | quantos relatórios manter (padrão 20; `0` = infinito) |
| `--allow-tool-failure` | não sair com código 2 quando uma ferramenta quebra |
| `--no-secrets` `--no-deps` `--no-sast` | pula uma das camadas |
| `-v` | mostra a saída das ferramentas |

### Rulesets por stack

Quando não se passa `--semgrep-config`, o secscan detecta a stack pelos arquivos na raiz do
projeto e soma os rulesets correspondentes ao `p/default`:

`package.json`/`package-lock.json` → `p/nodejs` · `requirements.txt`/`poetry.lock` → `p/python` ·
`go.mod` → `p/golang` · `pom.xml` → `p/java` · `Gemfile` → `p/ruby` · `composer.json` → `p/php` ·
`Cargo.toml` → `p/rust` · `*.csproj` → `p/csharp`

Achados duplicados entre rulesets sobrepostos são removidos automaticamente.

## Saída

Console resumido + `security-report/<timestamp>/` com:

- `relatorio.md` — estado de cada camada, tabela por severidade, instruções de correção
- `secscan.sarif` — SARIF 2.1.0, para GitHub code scanning / GitLab / Azure DevOps
- `gitleaks.json`, `osv.json`, `semgrep.json` — saída bruta de cada ferramenta

## Baseline: o que faz a ferramenta sobreviver ao uso contínuo

Sem baseline, a segunda execução reporta os mesmos 38 achados da primeira e você não consegue
ver **o que é novo**. Na prática, o relatório vira ruído e ninguém mais lê.

O baseline registra os achados que você decidiu aceitar. Aceitar tudo de uma vez:

```bash
./secscan.sh ../meu-projeto --write-baseline
```

Isso grava `<alvo>/.secscanignore` — commite esse arquivo junto com o projeto. A partir daí,
só achados novos aparecem, e o código de saída reflete apenas eles.

Para voltar a reportar um achado, apague a linha correspondente no `.secscanignore`.

O fingerprint é calculado sobre `ferramenta + regra + caminho + índice de ocorrência`, **sem o
número da linha** — então editar o arquivo e mover o código não faz o achado reaparecer.

## Códigos de saída

| Código | Significado |
|---|---|
| `0` | limpo |
| `1` | achado na severidade definida em `--fail-on` (padrão `alta`) |
| `2` | **alguma ferramenta falhou — varredura incompleta** |

O código `2` existe porque um scanner de segurança que falha em silêncio é pior que um que
quebra. Se o formato do JSON de uma ferramenta mudar, o secscan marca a camada como `FALHOU`
em vez de reportar "nada encontrado".

## Como interpretar

**CRÍTICA** — corrija hoje. Segredo exposto ou CVE com CVSS ≥ 9.0.
Segredo é sempre crítico porque não basta remover do código: se foi commitado, considere vazado
e **revogue** a credencial.

**ALTA** — corrija nesta sprint. CVSS 7.0–8.9, ou padrão de código explorável.

**MÉDIA** — corrija no ciclo. CVSS 4.0–6.9, ou padrão suspeito que depende de contexto.

O relatório aponta *onde*, não *se é explorável no seu caso*. Um `eval()` num script que só lê
config local não é o mesmo que um `eval()` numa rota HTTP. Confirme o caminho do dado antes de
tratar como urgente.

## Testes

```bash
.venv/bin/python -m unittest discover -s tests -v      # Linux/macOS
.venv\Scripts\python.exe -m unittest discover -s tests -v   # Windows
```

33 testes cobrindo o parsing das três ferramentas, mapeamento de severidade, fingerprints,
baseline e geração de SARIF. O parsing é feito em funções puras justamente para poder ser
testado sem rodar os binários.

## Limites

- **SAST não prova exploração.** Aponta padrão de risco. Falso positivo é normal — calibre as
  regras com o tempo.
- **A camada de dependências precisa de lockfile** (`package-lock.json`, `poetry.lock`,
  `go.sum`, `composer.lock`...). Sem ele, o osv-scanner aparece como "pulado" — e é justamente
  a camada que mais rende na prática.
- **Não substitui pentest.** Isso pega o que já é conhecido e automatizável. Falha de lógica de
  negócio (usuário A acessando pedido do usuário B) só um humano com contexto encontra.

## Segurança dos dados

Os segredos são **redigidos** no JSON por padrão (`"Secret": "REDACTED"`). Para obter o valor
real — necessário quando a credencial precisa ser revogada — use `--reveal-secrets`, que
desliga a redação. Nesse caso o relatório passa a conter a credencial em texto claro: apague
depois de usar.

`security-report/` está no `.gitignore` — não commite.

## Uso autorizado

Ferramenta para auditar código que é seu ou que você tem autorização para testar.
Testar sistema de terceiros sem permissão escrita é crime no Brasil (Lei 12.737/2012)
e na maioria das jurisdições.

## Licença

MIT — veja [LICENSE](LICENSE).
