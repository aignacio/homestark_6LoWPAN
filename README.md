#Projeto HomeStark :coffee:
 _   _                      ____  _             _    
| | | | ___  _ __ ___   ___/ ___|| |_ __ _ _ __| | __
| |_| |/ _ \| '_ ` _ \ / _ \___ \| __/ _` | '__| |/ /
|  _  | (_) | | | | | |  __/___) | || (_| | |  |   <
|_| |_|\___/|_| |_| |_|\___|____/ \__\__,_|_|  |_|\_\

>make TARGET=srf06-cc26xx

Desenvolvedor: Ânderson Ignácio da Silva

Projeto de TCC para criação de uma rede mesh 6LoWPAN utilizando o
target cc2650 da Texas Instruments. O dispositivo será capaz de se
conectar a uma rede mesh 6LoWPAN, comunicando via MQTT-SN com broker
remoto e local através de um interface de gestão/configuração.

Características:
- [ ] Suporte completo a MQTT-SN
- [ ] DTLS sobre UDP
- [ ] Informação ao border router sobre o nó
- [ ] Comunicação com periféricos e afins
- [ ] Documentação em Doxygen

Nomenclaturas:

ETX (expected transmission count) = Medidor de qualidade de caminho
entre dois nós em um pacote wireless de rede. Basicamente esse núme
ro indica o número esperado de transmissões de um pacote necessária
s para que não haja erro na recepção no destino.
