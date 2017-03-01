import { expect } from 'chai';
import userReducer from '../app/reducers/user';
import connectReducer from '../app/reducers/connect';
import settingsReducer from '../app/reducers/settings';
import { defaultServer } from '../app/config';
import { LoginState, ConnectionState } from '../app/enums';

describe('reducers', () => {

  it('should handle USER_LOGIN_CHANGE', () => {
    const action = {
      type: 'USER_LOGIN_CHANGE',
      payload: {
        account: '1111',
        status: LoginState.failed,
        error: new Error('Something went wrong')
      }
    }
    const test = Object.assign({}, action.payload);
    expect(userReducer({}, action)).to.deep.equal(test);
  });

  it('should handle CONNECTION_CHANGE', () => {
    const action = {
      type: 'CONNECTION_CHANGE',
      payload: {
        status: ConnectionState.connected,
        serverAddress: '2.1.1.2',
        clientIp: '2.1.1.1'
      }
    };
    const test = Object.assign({}, action.payload);
    expect(connectReducer({}, action)).to.deep.equal(test);
  });

  it('should handle SETTINGS_UPDATE', () => {
    const action = {
      type: 'SETTINGS_UPDATE',
      payload: {
        autoSecure: true,
        preferredServer: defaultServer
      }
    };
    const test = Object.assign({}, action.payload);
    expect(settingsReducer({}, action)).to.deep.equal(test);
  });

});