# secscan

[![tests](https://github.com/felixman255-droid/secscan/actions/workflows/test.yml/badge.svg)](https://github.com/felixman255-droid/secscan/actions/workflows/test.yml)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Varredura de segurança em um comando, para o **seu próprio** código.
Segredos, dependências, código-fonte e infraestrutura num único relatório.

## As quatro camadas

| Camada | Ferramenta | Pega o quê |
|---|---|---|
| Segredos | [gitleaks](https://github.com/gitleaks/gitleaks) 8.30.1 | token, chave de API, senha commitada |
| Dependências | [osv-scanner](https://github.com/google/osv-scanner) 2.7.1 | CVE em biblioteca de terceiros, com nota CVSS |
| Código (SAST) | [semgrep](https://semgrep.dev) 1.187 | injeção SQL, `eval`, `shell=True`, cripto fraca, XSS |
| Infraestrutura | [trivy](https://trivy.dev) 0.76.2 | Dockerfile e k8s inseguros: root, `privileged`, segredo em `ENV` |

Todas gratuitas. A camada de infraestrutura só roda quando há `Dockerfile`, `*.tf` ou manifesto
k8s; `docker-compose.yml` **não** é escaneado por ela. Detalhes em [limites](docs/limites.md).

## Instalação rápida

**Windows**

```powershell
git clone https://github.com/felixman255-droid/secscan.git
cd secscan
powershell -ExecutionPolicy Bypass -File install.ps1
```

**Linux / macOS**

```bash
git clone https://github.com/felixman255-droid/secscan.git
cd secscan
bash install.sh
```

Os binários são conferidos contra o SHA-256 oficial da release. Nada é instalado no sistema.

**Como skill do Claude Code:** clonar em `~/.claude/skills/secscan` e rodar o instalador lá.

**Como plugin do Claude Code** (2.1.275 ou mais novo):

```text
/plugin install secscan --marketplace felixman255-droid/secscan
```

No plugin, rodar o instalador uma vez na pasta dele; atualizações não exigem reinstalar, salvo
quando as versões das ferramentas mudam. Mais em [instalação](docs/instalacao.md).

## Uso pela linha de comando

```bash
./secscan.sh                          # pasta atual
./secscan.sh ../meu-projeto           # pasta específica
./secscan.sh ../meu-projeto --history # inclui o histórico do git
```

```powershell
& ".\secscan.cmd" "..\meu-projeto"
```

| Flag | Efeito |
|---|---|
| `--out DIR` | pasta de saída (padrão `security-report`) |
| `--history` | gitleaks varre o histórico **além** do working tree |
| `--baseline ARQ` | achados aceitos (padrão `<alvo>/.secscanignore`) |
| `--write-baseline` | grava o baseline com os achados atuais e encerra |
| `--fail-on NÍVEL` | `critica`, `alta` (padrão), `media`, `baixa` ou `nunca` |
| `--semgrep-config p/...` | troca o [ruleset](docs/rulesets.md); lista separada por vírgula |
| `--no-stack-rules` | não adiciona os rulesets da stack detectada |
| `--exclude-rule ID` | desliga uma regra; o relatório declara a exclusão |
| `--reveal-secrets` | não redige segredos no JSON |
| `--keep N` | quantos relatórios manter (padrão 20; `0` = todos) |
| `--allow-tool-failure` | não sai com 2 quando uma ferramenta quebra |
| `--no-secrets` `--no-deps` `--no-sast` `--no-iac` | pula uma camada |
| `--iac` | força a camada de infraestrutura |
| `--home` | mostra onde ficam as ferramentas |
| `-v` | mostra a saída das ferramentas |

| Código de saída | Significado |
|---|---|
| `0` | nada na severidade de `--fail-on` ou acima |
| `1` | achado na severidade de `--fail-on` |
| `2` | **alguma ferramenta falhou: varredura incompleta** |

## Uso por agente, em linguagem natural

Com a skill ou o plugin instalado (ou com o `AGENTS.md` no Codex, Cursor e afins), basta pedir:

```text
Audite a segurança de ../meu-projeto
Procure chaves vazadas neste repositório, inclusive no histórico
Essa dependência tem CVE?
```

O agente roda o `secscan`, confere se alguma camada falhou, resume por severidade e separa o que
é provável falso positivo.

## Exemplo de saída

Trecho de [examples/relatorio.md](examples/relatorio.md), gerado de um projeto fictício:

| Sev | Ferramenta | Local | Descricao | Corrigir para |
|---|---|---|---|---|
| CRÍTICA | gitleaks | `app.py:4` | Segredo exposto: github-pat | - |
| CRÍTICA | osv-scanner | `requirements.txt` | pyyaml 5.1.0 - PYSEC-2020-96 | 5.3.1 |
| ALTA | trivy | `Dockerfile` | DS-0002 - Image user should not be 'root' | - |
| MÉDIA | semgrep | `app.py:16` | Detected MD5 hash algorithm which is considered insecure... | - |
| BAIXA | trivy | `Dockerfile` | DS-0026 - No HEALTHCHECK defined | - |

Cada execução grava `relatorio.md`, `secscan.sarif` e os JSONs brutos. O relatório traz a seção
**Escopo**, com o que cada camada deixou de fora.

## Silenciar ruído: quatro níveis

| Nível | Mecanismo | Alcance | Aparece no relatório |
|---|---|---|---|
| 1. Linha | `# nosemgrep: <id>` | um ponto do código | não |
| 2. Caminho | `.semgrepignore` | diretórios, no semgrep | só o aviso em **Escopo** |
| 3. Regra | `--exclude-rule <id>` | uma regra no projeto todo | **Regras desativadas**, com a contagem |
| 4. Achado | `.secscanignore` (baseline) | um achado julgado | **Aceitos por baseline** |

Exemplo de baseline: [examples/.secscanignore](examples/.secscanignore). Antes de aceitar
qualquer coisa, ler [baseline e supressão](docs/baseline-e-supressao.md).

## Documentação

| Página | Conteúdo |
|---|---|
| [Instalação](docs/instalacao.md) | verificação de hashes, uso offline, compatibilidade com agentes |
| [Baseline e supressão](docs/baseline-e-supressao.md) | fingerprint, os três baldes da triagem, primeira execução |
| [Rulesets](docs/rulesets.md) | stacks detectadas, troca de ruleset, docker-compose |
| [Limites](docs/limites.md) | o que não é coberto, severidades, dados sensíveis |
| [Desenvolvimento](docs/desenvolvimento.md) | testes, contrato do projeto, saídas, CI |
| [Armadilhas](docs/armadilhas.md) | o que não regredir no código |

Para CI, há um workflow pronto em [examples/github-actions.yml](examples/github-actions.yml).

## Uso autorizado

Para auditar código que é seu ou que você tem autorização para testar. Testar sistema de terceiros
sem permissão escrita é crime no Brasil (Lei 12.737/2012) e na maioria das jurisdições.

## Licença

MIT. Veja [LICENSE](LICENSE).
