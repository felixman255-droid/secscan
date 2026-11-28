# Armadilhas de API (não regredir)

Ler antes de editar `secscan.py` ou os instaladores.

[← README](../README.md)

- gitleaks ≥ 8.19 **removeu** o subcomando `detect`. Usar `git` ou `dir`, com o alvo como
  **argumento posicional** — `--source` gera `unknown flag`.
- `gitleaks git` varre **apenas commits**. Um segredo presente no working tree mas não
  commitado é invisível nesse modo — por isso `--history` executa `git` **e** `dir` e une os
  resultados. Não "simplificar" para um modo só.
- A detecção do gitleaks é **específica de formato**. Valores sintéticos plausíveis não são
  detectados: `AKIAIOSFODNN7EXAMPLE` está allowlistado por ser o exemplo canônico da AWS, e um
  `sk-proj-...` inventado pode não casar com nenhuma regra. Não concluir "limpo" a partir de
  teste com valor de mentira.
- `osv-scanner` expõe `groups[].max_severity` como **nota CVSS numérica** ("8.7"), não rótulo.
  Mapear por faixa: ≥9 CRÍTICA, ≥7 ALTA, ≥4 MÉDIA, >0 BAIXA.
- `semgrep` marca `confidence: LOW` em regras de segredo e SQLi por heurística. **Não** rebaixar
  severidade por isso — rebaixar esconde chave de API exposta.
- `semgrep` com `--config` apontando para arquivo inexistente **sai com código 0** e só emite
  "unable to find a config". Sem validar antes, a camada apareceria como `ok` com zero achados.
  `missing_configs()` barra isso antes de rodar.
- No Git Bash, caminho `/c/...` passado como argumento solto é convertido para `C:/...`; dentro
  de uma lista separada por vírgula **não** é, e o semgrep recebe `\c\...` inválido. Em
  Windows, usar sempre `C:/...`.
- `trivy config` reporta PASS e FAIL no mesmo array `Misconfigurations`. Filtrar por
  `Status == "FAIL"`, senão o relatório enche de "está correto".
- `trivy config` **omite a chave `Results`** quando não detecta nenhum arquivo de config (ex.:
  `k8s/*.yaml` que ele não reconhece como Kubernetes). Isso é relatório válido, não schema
  quebrado: `parse_trivy` retorna `[]` quando há `SchemaVersion` + `ArtifactName`, e só levanta
  erro se o JSON não tiver nenhuma marca do trivy. Tratar como falha gerava `rc=2` falso.
- `trivy config` **não escaneia `docker-compose.yml`**: `dockercompose` não está em
  `--misconfig-scanners` (default: azure-arm, cloudformation, dockerfile, helm, kubernetes,
  terraform, terraformplan-*, ansible) e passar `--misconfig-scanners dockercompose` é
  ignorado em silêncio — nome de scanner inválido **não** gera erro. Por isso compose não
  entra em `detect_iac`.
- `trivy config` **renderiza Helm** (`Type: helm`): um `privileged: true` que existe só em
  `values.yaml` e chega ao template via `{{ toYaml .Values.securityContext }}` é detectado.
  Mas ele usa os values default — um `values-prod.yaml` com override não é considerado.
- `trivy config` usa `CauseMetadata.StartLine`, que **pode estar ausente** (regra de arquivo
  inteiro, ex. "no HEALTHCHECK"). Não assumir inteiro.
- `trivy config --skip-dirs` casa por **glob**, e nome simples (`node_modules`) só casa no
  **nível raiz** — `apps/web/node_modules` escapa. Usar sempre `**/node_modules`. O
  `trivy_cmd()` já monta assim; não simplificar para o nome puro.
- `trivy config` sem `--skip-check-update` tenta baixar o bundle OCI de checks **a cada
  execução**. Offline isso custa ~7s e um `ERROR` antes de cair no bundle embutido. A flag
  corta a tentativa de rede por completo — é o que garante o contrato offline, não o cache.
- Com `--skip-check-update`, o trivy **lê o cache se existir** e só cai no bundle embutido
  quando o cache está vazio. O `secscan` aponta `--cache-dir` para `cache/trivy` e **não
  pré-aquece**: cache vazio + flag = bundle embutido sempre, igual em qualquer SO. Se alguém
  "otimizar" pre-aquecendo, Windows (bug de path no download) passa a divergir de Linux/macOS.
- Não reportar "trivy precisa de rede". Ele embute os checks e funciona offline com o cache
  vazio — verificado: cache inexistente + registry inválido ainda rende os mesmos achados.
- No Windows o download OCI do trivy quebra quando o diretório temporário tem espaço ou está
  em outro drive: baixa para `F:\...` e depois tenta abrir `/...` (perde a letra do drive).
  Cai no bundle embutido e ainda sai com `rc=0`. **Nunca inferir sucesso do exit code.**
  Por isso não se contorna `TMP`/`TEMP`: exigiria escrever fora da pasta da skill e o
  resultado já é correto e determinístico com o bundle embutido.
- Não habilitar os scanners `vuln` e `secret` do trivy: duplicam osv-scanner e gitleaks.
- `gitleaks dir` não respeita `.gitignore`. O `secscan.py` gera um TOML temporário com
  `[extend] useDefault = true` e `[[allowlists]] paths` para ignorar **apenas** `node_modules`,
  `.venv`, `dist`, `build`, `target`, `vendor`, `.next`, `.next-*` e afins (SKIP_DIRS; `*` não
  atravessa barra). Casa só segmento inteiro de
  diretório e roda com `cwd=alvo`; ver `skip_pattern` e `gitleaks_cmd`. O relatório declara em
  **Escopo** o que cada camada deixou de fora: ler essa seção antes de dizer que está limpo.
- **Não herdar o `.gitignore` do alvo na allowlist do gitleaks.** Num scanner de segredos isso
  esconde exatamente o que importa: `.env`, `*.pem`, `credentials.json` são gitignorados por
  conterem segredo. Medido: com `*.pem` no `.gitignore`, uma chave RSA real de 2048 bits não
  era reportada; sem a linha, aparecia.
- Console do Windows não está em UTF-8: a saída do terminal usa rótulos sem acento
  (`CRITICA`), e o `relatorio.md` mantém a acentuação correta.
- `subprocess.run(text=True)` no Windows decodifica com o **locale** (cp1252), não com UTF-8 —
  saída acentuada das ferramentas vira mojibake. Sempre passar `encoding="utf-8",
  errors="replace"` explicitamente.
- As versões das ferramentas são fixas porque o parsing depende do JSON de cada uma, e os
  instaladores conferem o SHA-256 oficial antes de usar o binário. Ao subir versão, atualizar
  os hashes **e** rodar `python -m unittest discover -s tests`.
- `examples/compose-rules.yml` cobre docker-compose via Semgrep, opt-in com `--semgrep-config`.
- A allowlist casa **segmento inteiro de diretório** (`skip_pattern`). Nome solto como regex
  escondia `.github/`, `.gitlab-ci.yml`, `buildspec.yml` e `distance.py` (medido).
- `gitleaks dir` compara a allowlist com o caminho como o alvo foi passado. Rodar com `cwd=alvo`
  e alvo `.`: com caminho absoluto, um pai chamado `build` zerava a camada. No modo `git` o
  caminho é relativo à raiz do repositório, então o padrão leva o `rev-parse --show-prefix`.
- `osv-scanner --x-exclude`: usar `g:**/<pasta>`. Com `/**` no fim a própria pasta não é
  excluída, e um ancestral do alvo com o mesmo nome zera a varredura como "nenhum lockfile".
- `SKIP_DIRS` aceita `*` dentro de um nome de pasta (`.next-*`). Comparar nomes com
  `is_skipped_dir`, nunca com `in SKIP_DIRS`.
- A seção **Escopo** do relatório sai das constantes. Limite novo de cobertura entra lá.
