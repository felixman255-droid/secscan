# secscan

Varredura de segurança em um comando, para o **seu próprio** código.
Quatro camadas — segredos, dependências, código-fonte e infraestrutura — num único relatório.

```bash
./secscan.sh /caminho/do/seu-projeto
```

```
  gitleaks       ok (1.0s)
  osv-scanner    ok (4.3s)
  semgrep        ok (12.4s)
  trivy          ok (2.8s)

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
| Infraestrutura | [trivy](https://trivy.dev) 0.76.2 | Dockerfile e k8s inseguros: container como root, `privileged`, segredo em `ENV` |

Todas gratuitas. Depois da primeira execução, rodam offline.

A camada de infraestrutura só roda quando existe `Dockerfile`, `*.tf` ou manifesto k8s no
projeto — sem isso ela aparece como "pulado", sem custo de tempo. Para forçar mesmo assim, use
`--iac`.

**`docker-compose.yml` não é escaneado.** O Trivy 0.76 não tem scanner de compose (`Detected
config files num=0`), então o arquivo não ativa a camada. Se o projeto só tiver compose, o
relatório diz isso explicitamente em vez de reportar "limpo" — fingir cobertura seria pior que
admitir a lacuna.

O Trivy entra **só com o scanner `misconfig`**. Os scanners `vuln` e `secret` dele duplicariam
o osv-scanner e o gitleaks: mais ruído, zero cobertura nova.

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

Cria `bin/` (gitleaks + osv-scanner + trivy portáteis) e `.venv/` (semgrep isolado). Nada é
instalado no sistema — só arquivos nesta pasta.

Os três binários são conferidos contra o **SHA-256 oficial** da release fixada antes de serem
usados. Se o hash não bater, o instalador aborta e descarta o arquivo — não existe caminho que
aceite um binário não verificado. Os hashes estão embutidos nos scripts, um por arquitetura
(`x64`/`amd64` e `arm64`).

Ao final, os 9 rulesets do semgrep são pré-baixados para o cache local, para que a primeira
execução já funcione offline.

O trivy funciona de forma diferente, e de propósito. Ele recebe `--cache-dir` apontando para
`cache/trivy` — que fica **vazio**, porque o instalador não pré-aquece nada — junto com
`--skip-check-update`. Nesse estado o `trivy config` usa o bundle de checks **embutido no
binário 0.76.2**, sem tocar na rede. Isso dá três garantias de uma vez:

- **offline de verdade** — nenhuma tentativa de download durante a varredura;
- **determinismo** — os checks ficam atrelados à versão fixada do binário, iguais em Windows,
  Linux e macOS, e imunes a um cache quente de outra versão do trivy no sistema;
- **isolamento** — nada é escrito em `~/.cache/trivy` nem em `%LOCALAPPDATA%\trivy`.

Pré-aquecer o bundle OCI seria pior: o download quebra no Windows quando o caminho temporário
tem espaço, então Linux/macOS usariam o bundle OCI e o Windows cairia no embutido — máquinas
diferentes passariam a reportar achados diferentes.

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
| `--history` | gitleaks varre o histórico do git **além** do working tree — acha segredo que foi apagado |
| `--baseline ARQ` | arquivo de achados aceitos (padrão `<alvo>/.secscanignore`) |
| `--write-baseline` | grava o baseline com os achados atuais e encerra |
| `--semgrep-config p/...` | troca o ruleset; aceita lista separada por vírgula |
| `--no-stack-rules` | não adiciona os rulesets da stack detectada |
| `--exclude-rule ID` | desliga uma regra pelo id (o da coluna **Regra** do relatório); o relatório declara a exclusão e quantos achados ela cobriu |
| `--reveal-secrets` | não redigir segredos no JSON (necessário para revogar credencial) |
| `--keep N` | quantos relatórios manter (padrão 20; `0` = infinito). Relatórios marcados com `SENSIVEL.txt` são exceção: só o mais recente sobrevive |
| `--allow-tool-failure` | não sair com código 2 quando uma ferramenta quebra |
| `--no-secrets` `--no-deps` `--no-sast` `--no-iac` | pula uma das camadas |
| `--iac` | força a camada de infraestrutura mesmo sem IaC detectado |
| `-v` | mostra a saída das ferramentas |

### Rulesets por stack

Quando não se passa `--semgrep-config`, o secscan detecta a stack pelos manifestos e soma os
rulesets correspondentes ao `p/default`:

`package.json`/`package-lock.json` → `p/nodejs` · `requirements.txt`/`poetry.lock` → `p/python` ·
`go.mod` → `p/golang` · `pom.xml` → `p/java` · `Gemfile` → `p/ruby` · `composer.json` → `p/php` ·
`Cargo.toml` → `p/rust` · `*.csproj` → `p/csharp`

A busca desce até 3 níveis, então monorepos (`services/api/go.mod`, `apps/web/package.json`)
são detectados — não só a raiz. Diretórios de build e dependência são ignorados, e a varredura
para assim que todas as stacks conhecidas foram encontradas.

Achados duplicados entre rulesets sobrepostos são removidos automaticamente.

### Trocar o ruleset: medir, não assumir

É tentador trocar `p/default` por um pacote "só de vulnerabilidade" (`p/security-audit`,
`p/owasp-top-ten`) para reduzir ruído. **Menos achados não significa menos falso positivo —
pode significar menos cobertura.** Medição num projeto Python de teste com 5 problemas
plantados (chave AWS, PAT do GitHub, SQL injection, `eval`, MD5):

| Configuração | Achados | O que deixou passar |
|---|---|---|
| `p/default` + `p/python` | 5 | — |
| `p/security-audit` + `p/python` | 3 | **chave AWS** e **SQL injection** |
| `p/owasp-top-ten` + `p/python` | 2 | os acima + `eval` |

Os dois pacotes mais estreitos descartaram justamente as duas categorias de maior peso:
credencial exposta e injeção. Antes de trocar, compare **regra por regra** entre as
configurações, não a contagem total.

O caminho mais seguro para ruído continua sendo o baseline: mantenha `p/default` (cobertura) e
use `.secscanignore` para exceção deliberada. Baseline esconde o que você já julgou; ruleset
estreito esconde o que você nunca viu.

Os rulesets fora do `p/default` e das stacks não vêm pré-cacheados pelo instalador — a primeira
execução com eles precisa de rede.

### Regras próprias para docker-compose

Como o Trivy não escaneia compose, `examples/compose-rules.yml` traz regras de Semgrep para o
que mais importa nesses arquivos: `privileged: true`, socket do Docker montado,
`network_mode: host` e `user: root`.

```bash
./secscan.sh ../meu-projeto \
  --semgrep-config p/default,examples/compose-rules.yml
```

Entra na camada SAST que já existe, herdando fingerprint de baseline, mapeamento de severidade e
saída SARIF — sem código novo. É opt-in de propósito: são regras estruturais de YAML, não um
parser de compose, e por isso **não** resolvem `extends`, âncoras/merge (`<<: *defaults`) nem
valores alternativos como `privileged: "true"` entre aspas.

Passar um `--semgrep-config` que não existe no disco marca a camada como `FALHOU` (código de
saída `2`) em vez de reportar zero achados: "limpo" e "não rodou" são coisas diferentes.

O mesmo vale para config que existe mas é inválida — YAML malformado, regra sem `id`. Nesse caso
o semgrep **escreve o JSON normalmente** (com `results` vazio) e sai com `rc=7`; checar só a
existência do relatório transformaria um erro de configuração em "projeto limpo". O secscan
checa o código de saída (`0` e `1` são sucesso; `1` significa achados) e, como segunda rede, se
o JSON veio sem nenhum arquivo analisado **e** com erros registrados.

## Saída

Console resumido + `security-report/<timestamp>/` com:

- `relatorio.md` — estado de cada camada, tabela por severidade com a coluna **Corrigir para**
  (versão mínima segura extraída do advisory, quando o OSV a informa) e instruções de correção
- `secscan.sarif` — SARIF 2.1.0, para GitHub code scanning / GitLab / Azure DevOps
- `gitleaks.json`, `osv.json`, `semgrep.json`, `trivy.json` — saída bruta de cada ferramenta
  (com `--history`, também `gitleaks-dir.json`: a varredura do working tree)

O topo do `relatorio.md` marca todo o conteúdo como **dado não confiável**: nomes de arquivo e
mensagens vêm do projeto auditado, que pode ser de terceiros. Um agente que lê esse relatório
deve tratá-lo como dado, nunca como instrução.

## Baseline: o que faz a ferramenta sobreviver ao uso contínuo

Sem baseline, a segunda execução reporta os mesmos 38 achados da primeira e você não consegue
ver **o que é novo**. Na prática, o relatório vira ruído e ninguém mais lê.

**Antes de aceitar, meça a concentração.** Se uma regra genérica responde por metade dos achados,
o problema é a regra, não os 25 achados — e 25 linhas no baseline escondem isso:

```bash
jq -r '.results[].check_id' security-report/*/semgrep.json | sort | uniq -c | sort -rn | head
```

Contagem alta de um mesmo id pede `--exclude-rule` (ou `.semgrepignore`, se o ruído está num
diretório). Baseline é para **exceção de contexto** — o `subprocess` com argumento fixo, o
template já sanitizado —, não para repetição. Em config local o `check_id` sai com o prefixo do
diretório; o id que vale desativar é o sufixo, o mesmo que o relatório mostra.

O baseline registra os achados que você decidiu aceitar. Aceitar tudo de uma vez:

```bash
./secscan.sh ../meu-projeto --write-baseline
```

Isso grava `<alvo>/.secscanignore` — commite esse arquivo junto com o projeto. A partir daí,
só achados novos aparecem, e o código de saída reflete apenas eles.

Para voltar a reportar um achado, apague a linha correspondente no `.secscanignore`.

O fingerprint é calculado sobre `ferramenta + regra + caminho + trecho de código que casou a
regra`, **sem o número da linha**. Mover código, corrigir outra ocorrência ou reordenar achados
não faz um item já aceito reaparecer. No gitleaks o trecho é o `Match` redigido (`VARIAVEL=REDACTED`), e no semgrep sem login é
lido do arquivo. Sem nada que identifique (um token solto na linha), cai no índice de ocorrência:
**não aceitar esses no baseline**, porque a aceitação passa para outro segredo da mesma regra.
Aceitar um `VARIAVEL=...` vale para qualquer valor que essa variável venha a ter.

Regra local (`--semgrep-config examples/compose-rules.yml`) tem um detalhe que quebrava o
baseline: o semgrep monta o id como `<diretório-da-config>.<id-da-regra>`, com o caminho
sanitizado dentro. Como o id entra no fingerprint, um `.secscanignore` gravado em uma máquina
não casava em outra — todo achado virava "novo". O secscan remove esse prefixo e guarda só o id
da regra (`test-eval`, não `F.TemporariosdoGabriel.projeto.test-eval`), o que também deixa a
coluna **Regra** do relatório legível.

A sanitização não é "trocar separador por ponto": o semgrep relativiza ao diretório de trabalho
quando o arquivo está abaixo dele, remove os separadores iniciais (`lstrip("./")`) e **apaga**
os caracteres fora de `[A-Za-z0-9._-]`. Por isso `/tmp/x/regras.yml` vira `tmp.x.` no Linux e
`C:\x\regras.yml` vira `C.x.` no Windows. Chutar a regra acerta uma plataforma e erra a outra —
e o erro é silencioso, porque o strip que não casa simplesmente mantém o id completo.

## Silenciar ruído: quatro níveis, do mais local ao mais amplo

Todos deixam rastro versionado no repositório — nenhum é um ponto cego invisível.

**1. Linha específica — `# nosemgrep`.** Suprime uma regra naquele ponto e a justificativa fica
no `git blame`. É o mecanismo mais preciso:

```python
return hashlib.md5(senha.encode()).hexdigest()  # nosemgrep: python.lang.security.insecure-hash-algorithms-md5.insecure-hash-algorithm-md5
```

Sem o id da regra, `# nosemgrep` suprime **todas** as regras naquela linha — funciona, mas perde
a especificidade e esconde regressão futura.

**2. Caminho inteiro — `.semgrepignore`.** Exclui diretórios de baixa criticidade sem tocar no
comando nem no cache. Funciona mesmo com o `--no-git-ignore` que o `secscan` passa (verificado):

```
legacy/
fixtures/
```

**3. Regra inteira — `--exclude-rule`.** Para a regra que é barulhenta no projeto todo, não em um
ponto. Não existe equivalente em arquivo de configuração quando o ruleset vem do registry
(`p/default`), então a saída é desligar pelo id:

```bash
./secscan.sh ../meu-projeto --exclude-rule python.lang.security.audit.subprocess-shell-true.subprocess-shell-true
```

O id é o mesmo que aparece na coluna **Regra** do relatório. A exclusão age no **resultado**, não
na varredura: o `semgrep.json` bruto continua com os achados (a evidência não some) e o relatório
declara quantos cada regra desligada suprimiu — `test-eval — 2 achado(s) suprimido(s)`. Se você
esperava achados e o número vier zero, o id está errado: id que não casa nada passa em silêncio
no semgrep, então esse zero é o único aviso que existe.

Repassar `--exclude-rule` ao semgrep foi a primeira tentativa e está errado por três motivos: o
`skipped_rules` do JSON vem sempre vazio (não há como contar o que foi suprimido), a flag casa
com o `check_id` cru (que em config local carrega o prefixo do diretório) e um id inválido é
aceito sem erro — o relatório anunciaria uma exclusão que nunca aconteceu.

**4. Achado aceito — `.secscanignore`.** O baseline. Diferente dos três anteriores: age no
resultado, não na varredura, então o achado continua sendo detectado e apenas não conta como
novo. É o único dos quatro que aparece no relatório, na seção **Aceitos por baseline** — com
ferramenta, local e regra, para você conferir a aceitação sem abrir o arquivo do baseline.

Um detalhe que pega as pessoas: **`tests/` e `test/` já são excluídos pelo Semgrep por padrão.**
Não é preciso `.semgrepignore` para eles — e vale saber que código dentro dessas pastas **nunca**
é analisado, mesmo que não seja teste de verdade. `fixture/`, `spec/` e `src/` são varridos
normalmente.

### Os três baldes da triagem

Achado de SAST só orienta ação quando separado em três — e o relatório já entrega a separação
pronta:

| Balde | Como reconhecer | Mecanismo |
|---|---|---|
| **Ruído de regra** | o padrão não se aplica à arquitetura (regra de XSS num template que não renderiza HTML de usuário) | `--exclude-rule` — seção **Regras desativadas**, com a contagem que ela cobria |
| **Verdadeiro em contexto seguro** | o sink existe, mas a entrada é estática ou passa por whitelist | `# nosemgrep` no ponto ou `.secscanignore` — seção **Aceitos por baseline** |
| **Vulnerável acionável** | dado externo chega ao sink sem sanitização | corrigir o código — tabela **Achados** |

Uma taxa única de "falso positivo" mistura os três e não diz onde agir: ruído de regra pede
`--exclude-rule`, contexto seguro pede aceitação pontual, e só o terceiro balde pede código. Os
números de cada seção são o que separa os casos.

## Primeira execução em um projeto real

Ordem que evita os dois erros caros: congelar vulnerabilidade real no baseline, e ligar o CI
antes de saber qual é o ruído de base.

**1. Varredura completa, priorizando o que é urgente.**

```bash
./secscan.sh ../meu-projeto --history
```

Olhar primeiro os segredos (CRÍTICA, revogar em vez de só remover) e as CVEs com coluna
**Corrigir para** preenchida — essas têm correção determinística. SAST por último: é a camada
com mais falso positivo e a que menos muda a decisão de curto prazo.

**2. Triagem antes de gravar o baseline.**

Corrigir o que é real primeiro. `--write-baseline` serve para exceção deliberada — dependência
só de desenvolvimento, padrão interno isolado —, não para zerar o relatório. Baseline gravado
cedo demais congela vulnerabilidade de verdade e o time passa a ignorar a saída.

**3. CI só depois do baseline limpo.**

Com `.secscanignore` commitado, o workflow barra apenas regressão nova (`--fail-on alta`). Ligar
antes disso produz um pipeline vermelho permanente, que é a forma mais rápida de ensinar o time
a ignorar alerta.

Duas coisas que a verificação ponta a ponta confirmou e que valem saber:

- O baseline é **estável**: duas execuções seguidas geram `.secscanignore` idêntico, e um
  segredo novo (mesmo não commitado) derruba a execução com `rc=1`. Sem essa estabilidade, todo
  commit acusaria falha falsa.
- Teste com valor sintético **não prova nada**. `AKIAIOSFODNN7EXAMPLE` está allowlistado pelo
  gitleaks por ser o exemplo canônico da AWS, e uma chave inventada pode não casar com regra
  nenhuma. Um "limpo" obtido assim é falso negativo do teste, não do código.

## Códigos de saída

| Código | Significado |
|---|---|
| `0` | limpo |
| `1` | achado na severidade definida em `--fail-on` (padrão `alta`) |
| `2` | **alguma ferramenta falhou — varredura incompleta** |

O código `2` existe porque um scanner de segurança que falha em silêncio é pior que um que
quebra. Se o formato do JSON de uma ferramenta mudar, o secscan marca a camada como `FALHOU`
em vez de reportar "nada encontrado".

Se o semgrep abortar sem gravar o JSON (timeout, falta de memória), a camada traz
`semgrep sem relatorio (rc=..., Ns)` e o fim da saída; `rc=124` é o limite de 30 minutos.

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

119 testes cobrindo o parsing das quatro ferramentas, mapeamento de severidade, fingerprints por
conteúdo, baseline (inclusive portabilidade do id de regra local entre caminhos **e** entre
Windows e POSIX), detecção de stack em monorepo, allowlist do gitleaks (sem herdar `.gitignore`),
detecção de IaC (inclusive o que o trivy não escaneia, e charts aninhados), relatório vazio do
trivy, montagem
do comando do trivy (globs de exclusão e flag offline), validação de `--semgrep-config` local
(ausente **e** inválida), seção de aceitos por baseline no relatório,
modos de execução do gitleaks (histórico + working tree), escolha de ruleset padrão,
retenção de relatório sensível, geração de SARIF e os invariantes do contrato (cache hermético,
sem pré-aquecimento).
O parsing é feito em funções puras justamente para poder ser testado sem rodar os binários.

O CI roda a suíte em **`ubuntu-latest` e `windows-latest`** — a suíte é Python puro, não baixa
binário, então a matriz custa segundos. Foi uma matriz que faltava: o commit `2509e0a` passou no
Windows e quebrou no Linux porque um teste montava expectativa de caminho com o `Path` da
plataforma. Regra da casa: teste que envolve caminho **não** usa o `Path` da plataforma para
montar a expectativa — usa `PurePosixPath` ou `PureWindowsPath` explicitamente, e valida os dois
formatos em qualquer máquina. A matriz é a segunda rede: se um teste voltar a depender de
semântica de sistema de arquivos, ela acusa no mesmo push.

## Contrato do projeto

As quatro camadas seguem o mesmo conjunto de invariantes. Quebrar qualquer um deles é
regressão, mesmo que os testes continuem passando.

| Garantia | Como é imposta | O que a quebraria |
|---|---|---|
| **Versões fixas** | `install.ps1`/`install.sh` fixam gitleaks, osv-scanner, trivy e conferem o SHA-256 oficial antes de usar | subir versão sem revalidar o parsing (`unittest`) |
| **Saída determinística** | parsing em funções puras; fingerprints por conteúdo, sem número de linha; baseline | usar heurística dependente de ordem ou de caminho absoluto |
| **Isolamento hermético** | tudo em `bin/`, `.venv/`, `cache/` dentro da pasta da skill; `--cache-dir` local | deixar uma ferramenta escrever em `~/.cache` ou `%LOCALAPPDATA%` |
| **Paridade entre plataformas** | nenhuma camada depende de estado de cache do sistema | pré-aquecer cache de forma condicional (funciona num SO, falha em outro) |

O caso mais sutil é a paridade. O trivy usa o bundle de checks **embutido no binário** porque o
`--cache-dir` aponta para uma pasta que fica vazia de propósito. Pré-aquecê-la parece uma
otimização inofensiva, mas o download OCI quebra no Windows quando o caminho temporário tem
espaço: Linux e macOS passariam a usar o bundle OCI e o Windows o embutido, e a mesma base de
código reportaria achados diferentes conforme a máquina. Por isso o instalador **não**
pré-aquece — e há comentário nos dois scripts explicando que isso é deliberado.

## Integração com CI

`examples/github-actions.yml` é um workflow pronto: instala com cache, roda com `--history`,
publica o SARIF no GitHub Security tab e só falha depois do upload. Copie para
`.github/workflows/secscan.yml` e ajuste o repositório de origem se usar um fork.

## Limites

- **Pastas de dependência e build não são lidas** por gitleaks, osv-scanner e trivy:
  `node_modules`, `dist`, `build`, `.next`, `.next-*` (builds paralelos do Next, como
  `.next-audit`) e as demais de `SKIP_DIRS`. O semgrep usa uma lista menor. A seção
  **Escopo** do `relatorio.md` mostra o que cada camada deixou de fora.
- Nenhuma camada lê `.next` e `.next-*`. Por isso **não há checagem automática de variável de
  servidor embutida por engano no bundle do navegador** (Next.js): conferir à mão em
  `.next/static` e `.next/server` quando isso importar.
- **SAST não prova exploração.** Aponta padrão de risco. Falso positivo é normal — calibre as
  regras com o tempo.
- **A camada de dependências precisa de lockfile ou `requirements.txt`.** O osv-scanner lê
  `requirements.txt`, `poetry.lock`, `uv.lock`, `Pipfile.lock`, `package-lock.json`,
  `go.mod`, `Cargo.lock`, `pom.xml`, `Gemfile.lock` e `composer.lock`. Manifestos puros
  (`pyproject.toml`, `package.json` sem lockfile ao lado) **são ignorados** — nesse caso a
  camada aparece como "pulado", e é justamente a que mais rende na prática. Projeto Python
  com só `requirements.txt` está coberto; projeto com só `pyproject.toml` não está.
- **Não substitui pentest.** Isso pega o que já é conhecido e automatizável. Falha de lógica de
  negócio (usuário A acessando pedido do usuário B) só um humano com contexto encontra.
- **Misconfig de infraestrutura não é vulnerabilidade de código.** O Trivy aponta configuração
  insegura (container como root, `privileged: true`, `latest` sem pin). Um `privileged: true`
  num cluster de teste local não tem o peso do mesmo campo em produção — o relatório não sabe
  distinguir os dois ambientes.
- **A camada de infraestrutura cobre só o que existe em arquivo.** Dockerfile, `.tf` e
  manifesto k8s versionado. Infra provisionada por console, ou imagem construída fora do
  repositório, fica invisível.
- **`docker-compose.yml` fica de fora.** O Trivy 0.76 não escaneia compose. Um
  `privileged: true` num compose só aparece se o arquivo for convertido para k8s ou revisado
  à mão — o `secscan` avisa quando encontra um.
- **A detecção de IaC desce até 3 níveis.** Chart Helm em `deploy/charts/app/Chart.yaml` é
  encontrado; em `a/b/c/d/Chart.yaml` (4 níveis) não é, e a camada fica "pulado". O
  `Chart.yaml` é detectado explicitamente porque fica um nível acima de `templates/`, que
  costuma cair fora do limite — o Trivy não tem esse limite e escaneia o chart inteiro quando
  a camada é ativada.
- **O trivy pode deixar de ver IaC dentro de pastas de dependência.** `node_modules/`,
  `vendor/` e `.terraform/` costumam trazer Dockerfiles de exemplo; o `secscan` os exclui de
  propósito para não reportar infra de terceiros. Se você mantém IaC versionado dentro de uma
  dessas pastas, ele não será escaneado.

## Segurança dos dados

Os segredos são **redigidos** no JSON por padrão (`"Secret": "REDACTED"`). Para obter o valor
real — necessário quando a credencial precisa ser revogada — use `--reveal-secrets`, que desliga
a redação.

Com `--reveal-secrets` ativo, o diretório do relatório recebe um marcador `SENSIVEL.txt` e o
console avisa. A rotação de `--keep` trata esses diretórios de forma especial: **apenas o mais
recente é preservado**, os anteriores são apagados mesmo dentro da janela de retenção, porque
acumular dumps de credencial em texto claro só aumenta a exposição sem ganho. Nesse estado o
relatório contém credenciais em texto claro:

- não commite, não anexe em ticket, não envie a serviço externo;
- se um agente de IA estiver operando, ele **não deve abrir** `gitleaks.json` — o valor iria
  para a janela de contexto e para o provedor do modelo. Nesse caso, o agente deve apenas
  informar o caminho do arquivo para você abrir localmente;
- apague o diretório depois de revogar as credenciais.

`security-report/` está no `.gitignore` — não commite.

## Uso autorizado

Ferramenta para auditar código que é seu ou que você tem autorização para testar.
Testar sistema de terceiros sem permissão escrita é crime no Brasil (Lei 12.737/2012)
e na maioria das jurisdições.

## Licença

MIT — veja [LICENSE](LICENSE).
