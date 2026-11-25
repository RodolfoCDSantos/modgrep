# modgrep

**modgrep** é um analisador de tráfego MODBUS TCP para terminal. Ele captura pacotes em tempo real ou lê arquivos PCAP, identifica transações MODBUS TCP e exibe detalhes como transaction ID, unit ID, function code, endereços de registradores e exceções.

O projeto é um **spin-off inspirado no [sngrep](https://github.com/irontec/sngrep)**, da [Irontec](https://www.irontec.com/). O sngrep é um excelente visualizador de fluxos SIP em terminal; o modgrep adapta essa ideia de inspeção de protocolo e interface de terminal para o protocolo MODBUS TCP.

## Créditos

- Inspirado em **sngrep**, criado e mantido pela **Irontec**: https://github.com/irontec/sngrep
- Obrigado à equipe do sngrep e à Irontec pela referência de arquitetura, experiência de uso em terminal e abordagem de captura de pacotes.
- Este projeto não contém código-fonte do sngrep; é uma implementação independente para MODBUS TCP.

## Recursos

- Captura ao vivo de tráfego MODBUS TCP.
- Leitura de arquivos `.pcap`.
- Filtro BPF configurável; por padrão, `tcp port 502`.
- Decodificação do cabeçalho MBAP.
- Identificação de function codes MODBUS.
- Detecção de respostas de exceção MODBUS.
- Saída legível no terminal.

## Instalação

### Debian / Ubuntu

```bash
sudo apt update
sudo apt install -y build-essential cmake libpcap-dev
```

### Fedora

```bash
sudo dnf install -y gcc cmake libpcap-devel
```

### Arch Linux

```bash
sudo pacman -S --needed base-devel cmake libpcap
```

## Compilação

```bash
git clone https://github.com/RodolfoCDSantos/modgrep.git
cd modgrep
cmake -S . -B build
cmake --build build
```

O binário será gerado em:

```text
build/modgrep
```

## Uso

### Captura ao vivo

```bash
sudo ./build/modgrep -i eth0
```

Substitua `eth0` pela sua interface de rede. Para listar interfaces disponíveis:

```bash
./build/modgrep --list-interfaces
```

### Analisar um arquivo PCAP

```bash
./build/modgrep -r captura.pcap
```

### Filtrar outra porta MODBUS

```bash
sudo ./build/modgrep -i eth0 -f "tcp port 1502"
```

## Exemplo de saída

```text
2026-11-25 19:50:01.123456 192.168.1.10:51234 -> 192.168.1.20:502
  MODBUS TCP  transaction=1 unit=1 function=Read Holding Registers (0x03)
  starting address=0 quantity=10

2026-11-25 19:50:01.125000 192.168.1.20:502 -> 192.168.1.10:51234
  MODBUS TCP  transaction=1 unit=1 function=Read Holding Registers (0x03)
  byte count=20 register values=...
```

## Limitações atuais

Esta é uma primeira versão funcional. Ainda não reconstrói mensagens MODBUS fragmentadas em múltiplos segmentos TCP nem correlaciona automaticamente requisições e respostas em uma interface interativa. Esses recursos estão planejados para as próximas versões.

## Licença

Distribuído sob a licença MIT. Consulte o arquivo [LICENSE](LICENSE).
