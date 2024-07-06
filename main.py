import nmap  # type: ignore

def show_osclasses(osclasses):
    for osclass in osclasses:
        print(f"\t\t---------------------OSCLASS-------------------------")
        print(f"\t\tTipo: {osclass['type']}")
        print(f"\t\tVendor: {osclass['vendor']}")
        print(f"\t\tOS Family: {osclass['osfamily']}")
        print(f"\t\tOS Gen: {osclass['osgen']}")
        print(f"\t\tExactitud: {osclass['accuracy']}")
        print(end="\n")


def show_osmatchs(hostScaned):
    osmatchs = hostScaned['osmatch']
    for osmatch in osmatchs:
        print("\t-------------------------OSMATCH-------------------------")
        print(f"\tNombre: {osmatch['name']}")
        print(f"\tExactitud: {osmatch['accuracy']}")
        print(f"\tLinea: {osmatch['line']}")
        show_osclasses(osmatch['osclass'])
    print("\t---------------------------------------------------------", end="\n\n")


def show_ports(ports, protocolScaned):
    print(f"\t\t----------------------------PORTS-------------------------")
    for port in ports:
        print(f"\t\tPuerto: {port}")
        print(f"\t\tEstado: {protocolScaned[port]['state']}")
        print(f"\t\tNombre: {protocolScaned[port]['name']}")
        print(f"\t\tProducto: {protocolScaned[port]['product']}")
        print(f"\t\tVersion: {protocolScaned[port]['version']}")
        print(f"\t\tInformacion extra: {protocolScaned[port]['extrainfo']}")
        print(f"\t\tConfiguracion: {protocolScaned[port]['conf']}")
        print(f"\t\tCpe: {protocolScaned[port]['cpe']}")
        print(end="\n")
    print("\t\t---------------------------------------------------------") if len(
        ports) > 0 else print('', end='')


def show_protocols(hostScaned):
    protocols = hostScaned.all_protocols()
    print("\t-------------------------PROTOCOLS-------------------------")
    for protocol in protocols:
        print(f"\tProtocolo: {protocol}")
        show_ports(hostScaned[protocol].keys(), hostScaned[protocol])
    print("\t---------------------------------------------------------", end="\n\n")


def showResults(nmapScaned):
    hosts = nmapScaned.all_hosts()
    print(f"Se encontraron {len(hosts)} hosts")
    for host in hosts:
        hostScaned = nmapScaned[host]
        print(f"Host: {host} con hostname ({hostScaned.hostname()})")
        print(f"Estado: {hostScaned.state()}")
        show_protocols(hostScaned)
        show_osmatchs(hostScaned)
    print("---------------------------------------------------------", end="\n\n")


def main():
    print("Bienvenido a la herramienta de escaneo python-nmap")
    print("Por favor, introduzca los siguientes datos para realizar el escaneo")
    print("Si no desea introducir un dato, presione enter")
    print(end="\n\n")
    host = input(
        "Introduzca la dirección del host, ej. 192.168.0.52 domain.com: ")
    ports = input(
        "Introduzca los puertos a escanear (separados por comas), ej. 22,80,443: ")
    arguments = input("Introduzca los argumentos del escaneo, ej. -sn -sL: ")
    arguments += " -O -sV --script=default"
    arguments = arguments.strip()
    sudo = input(
        "¿Desea ejecutar el escaneo como administrador? (y/n): ").lower() == "y"
    print(end="\n\n")
    print("Iniciando escaneo...")
    print(end="\n\n")
    # EJECUCION DEL CODIGO
    nmapScaned = nmap.PortScanner()
    nmapScaned.scan(hosts=host, ports=ports, arguments=arguments, sudo=sudo)
    # MOSTRAMOS LOS RESULTADOS
    showResults(nmapScaned)
    print("Escaneo finalizado")


if __name__ == "__main__":
    main()
