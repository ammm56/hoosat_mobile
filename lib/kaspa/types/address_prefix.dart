enum AddressPrefix {
  unknown,
  hoosat,
  hoosatTest,
  hoosatDev,
  hoosatSim;

  static AddressPrefix parseBech32Prefix(String prefix) {
    switch (prefix) {
      case 'hoosat':
        return AddressPrefix.hoosat;
      case 'hooosattest':
        return AddressPrefix.hoosatTest;
      case 'hoosatdev':
        return AddressPrefix.hoosatDev;
      case 'hoosatsim':
        return AddressPrefix.hoosatSim;
      default:
        return AddressPrefix.unknown;
    }
  }

  @override
  String toString() => name.toLowerCase();
}
