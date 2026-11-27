# Instalação no Teltonika RUT955 (RutOS)

Este guia descreve a instalação do `modgrep` em roteadores Teltonika RUT955 executando RutOS 7.x, por linha de comando.

Os pacotes `.ipk` foram compilados para a arquitetura `mips_24kc` (MIPS 74Kc). Eles são compatíveis com RUT950 e RUT955 que utilizem RutOS compatível com essa arquitetura. Não instale estes pacotes em roteadores Teltonika baseados em ARM, como muitas séries RUT2xx e RUTX.

## Pacotes necessários

- `libpcap1_1.9.1-3_mips_24kc.ipk`
- `libncurses6_6.2-1_mips_24kc.ipk`
- `terminfo_6.2-1_mips_24kc.ipk`
- `modgrep_0.2.1-1_mips_24kc.ipk`

O `mqttgrep` requer as mesmas dependências, além de `mqttgrep_0.1.0-1_mips_24kc.ipk`.

## 1. Acesse o roteador por SSH

```sh
ssh root@192.168.1.1
```

Substitua `192.168.1.1` pelo endereço IP do roteador.

## 2. Copie os pacotes

No computador, dentro da pasta que contém os `.ipk`:

```sh
scp *.ipk root@192.168.1.1:/tmp/
```

No roteador:

```sh
ls -lh /tmp/*.ipk
```

## 3. Verifique a arquitetura

```sh
opkg print-architecture
uname -m
```

A arquitetura esperada é `mips_24kc`.

## 4. Instale as dependências

```sh
opkg update
opkg install /tmp/libpcap1_1.9.1-3_mips_24kc.ipk
opkg install /tmp/libncurses6_6.2-1_mips_24kc.ipk
opkg install /tmp/terminfo_6.2-1_mips_24kc.ipk
```

## 5. Instale o modgrep

```sh
opkg install /tmp/modgrep_0.2.1-1_mips_24kc.ipk
```

## 6. Teste

```sh
modgrep --help
```

## 7. Desinstalação

```sh
opkg remove modgrep
opkg remove libncurses6
opkg remove libpcap1
```

## Solução de problemas

Se houver dependência ausente, instale primeiro `libpcap1`, `libncurses6` e `terminfo`.

Se houver erro de arquitetura, o firmware do roteador não é `mips_24kc`.
