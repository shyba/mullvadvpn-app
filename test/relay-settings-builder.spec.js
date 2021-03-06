// @flow

import RelaySettingsBuilder from '../app/lib/relay-settings-builder';

describe('Relay settings builder', () => {
  it('should set location to any', () => {
    expect(
      RelaySettingsBuilder.normal()
        .location.any()
        .build(),
    ).to.deep.equal({
      normal: {
        location: 'any',
      },
    });
  });

  it('should bound location to city', () => {
    expect(
      RelaySettingsBuilder.normal()
        .location.city('se', 'mma')
        .build(),
    ).to.deep.equal({
      normal: {
        location: {
          only: {
            city: ['se', 'mma'],
          },
        },
      },
    });
  });

  it('should bound location to country', () => {
    expect(
      RelaySettingsBuilder.normal()
        .location.country('se')
        .build(),
    ).to.deep.equal({
      normal: {
        location: {
          only: { country: 'se' },
        },
      },
    });
  });

  it('should set openvpn settings to any', () => {
    expect(
      RelaySettingsBuilder.normal()
        .tunnel.openvpn((openvpn) => {
          openvpn.port.any().protocol.any();
        })
        .build(),
    ).to.deep.equal({
      normal: {
        tunnel: {
          only: {
            openvpn: {
              port: 'any',
              protocol: 'any',
            },
          },
        },
      },
    });
  });

  it('should set openvpn settings to exact values', () => {
    expect(
      RelaySettingsBuilder.normal()
        .tunnel.openvpn((openvpn) => {
          openvpn.port.exact(80).protocol.exact('tcp');
        })
        .build(),
    ).to.deep.equal({
      normal: {
        tunnel: {
          only: {
            openvpn: {
              port: { only: 80 },
              protocol: { only: 'tcp' },
            },
          },
        },
      },
    });
  });

  it('should set location from raw RelayLocation', () => {
    expect(
      RelaySettingsBuilder.normal()
        .location.fromRaw('any')
        .build(),
    ).to.deep.equal({
      normal: {
        location: 'any',
      },
    });

    expect(
      RelaySettingsBuilder.normal()
        .location.fromRaw({ country: 'se' })
        .build(),
    ).to.deep.equal({
      normal: {
        location: {
          only: { country: 'se' },
        },
      },
    });

    expect(
      RelaySettingsBuilder.normal()
        .location.fromRaw({ city: ['se', 'mma'] })
        .build(),
    ).to.deep.equal({
      normal: {
        location: {
          only: { city: ['se', 'mma'] },
        },
      },
    });
  });

  it('should set custom endpoint settings', () => {
    expect(
      RelaySettingsBuilder.custom()
        .host('se2.mullvad.net')
        .tunnel.openvpn((openvpn) => {
          openvpn.port(80).protocol('tcp');
        })
        .build(),
    ).to.deep.equal({
      custom_tunnel_endpoint: {
        host: 'se2.mullvad.net',
        tunnel: {
          openvpn: {
            port: 80,
            protocol: 'tcp',
          },
        },
      },
    });
  });
});
