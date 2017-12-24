import React from 'react';
import { bindActionCreators } from 'redux';
import { connect } from 'react-redux';
import TextField from 'material-ui/TextField';
import RaisedButton from 'material-ui/RaisedButton';
import Paper from 'material-ui/Paper';
import * as actionCreators from '../actions/auth';
import { validateEmail } from '../utils/misc';
import axios from 'axios';
import { browserHistory } from 'react-router';


function mapStateToProps(state) {
    return {
        isRegistering: state.auth.isRegistering,
        registerStatusText: state.auth.registerStatusText,
    };
}

function mapDispatchToProps(dispatch) {
    return bindActionCreators(actionCreators, dispatch);
}

const style = {
    marginTop: 50,
    paddingBottom: 50,
    paddingTop: 25,
    width: '100%',
    textAlign: 'center',
    display: 'inline-block',
};

@connect(mapStateToProps, mapDispatchToProps)
export default class RegisterView extends React.Component {

    constructor(props) {
        super(props);
        const redirectRoute = '/login';
        this.state = {
            name: '',
            email: '',
            password: '',
            tel: '',
            email_error_text: null,
            password_error_text: null,
            tel_error_text: null,
            redirectTo: redirectRoute,
            disabled: true,
        };
    }

    isDisabled() {
        let email_is_valid = false;
        let password_is_valid = false;
        let tel_is_valid = false;

        if (this.state.email === '') {
            this.setState({
                email_error_text: null,
            });
        } else if (validateEmail(this.state.email)) {
            email_is_valid = true;
            this.setState({
                email_error_text: null,
            });

        } else {
            this.setState({
                email_error_text: 'Sorry, this is not a valid email',
            });
        }

        if (this.state.password === '' || !this.state.password) {
            this.setState({
                password_error_text: null,
            });
        } else if (this.state.password.length >= 6) {
            password_is_valid = true;
            this.setState({
                password_error_text: null,
            });
        } else {
            this.setState({
                password_error_text: 'Your password must be at least 6 characters',
            });

        }

        if (email_is_valid && password_is_valid) {
            this.setState({
                disabled: false,
            });
        }

        if (this.state.tel === '' || !this.state.tel) {
            this.setState({
                tel_error_text: null,
            });
        } else if (this.state.tel.length >=10 && this.state.tel.length <12) {
            this.setState({
                tel_error_text: null,
            });
        }else {
            this.setState({
                tel_error_text: 'Enter a valid phone number',
            });
        }

    }

    changeValue(e, type) {
        // console.log(process.env.REACT_APP_USERS_SERVICE_URL, "undefined?")
        const value = e.target.value;
        const next_state = {};
        next_state[type] = value;
        this.setState(next_state, () => {
            this.isDisabled();
        });
    }

    _handleKeyPress(e) {
        if (e.key === 'Enter') {
            if (!this.state.disabled) {
                this.login(e);
            }
        }
    }

    login(e) {
        // console.log(process.env.REACT_APP_USERS_SERVICE_URL)
        e.preventDefault();
        axios.post(`${process.env.REACT_APP_USERS_SERVICE_URL}/api/register`,
            {
            name: this.state.name,
            email: this.state.email,
            password: this.state.password,
            phone_number: this.state.tel,
        }
        ).then(function (response) {
            browserHistory.push('/discussions');
        })
        // this.props.registerUser(this.state.email, this.state.password, this.state.redirectTo);
    }

    render() {
        return (
            <div className="col-md-6 col-md-offset-3" onKeyPress={(e) => this._handleKeyPress(e)}>
                <Paper style={style}>
                    <div className="text-center">
                        <h2>{`${process.env.REACT_APP_USERS_SERVICE_URL}`}</h2>
                        {
                            this.props.registerStatusText &&
                                <div className="alert alert-info">
                                    {this.props.registerStatusText}
                                </div>
                        }

                        <div className="col-md-12">
                            <TextField
                              hintText="Name"
                              floatingLabelText="Name"
                              type="name"
                              onChange={(e) => this.changeValue(e, 'name')}
                            />
                        </div>
                        <div className="col-md-12">
                            <TextField
                              hintText="Email"
                              floatingLabelText="Email"
                              type="email"
                              errorText={this.state.email_error_text}
                              onChange={(e) => this.changeValue(e, 'email')}
                            />
                        </div>
                        <div className="col-md-12">
                            <TextField
                              hintText="Password"
                              floatingLabelText="Password"
                              type="password"
                              errorText={this.state.password_error_text}
                              onChange={(e) => this.changeValue(e, 'password')}
                            />
                        </div>
                        <div className="col-md-12">
                            <TextField
                              hintText="Phone number"
                              floatingLabelText="Phone number"
                              type="tel"
                              errorText={this.state.tel_error_text}
                              onChange={(e) => this.changeValue(e, 'tel')}
                            />
                        </div>

                        <RaisedButton
                          disabled={this.state.disabled}
                          style={{ marginTop: 50 }}
                          label="Submit"
                          onClick={(e) => this.login(e)}
                        />

                    </div>
                </Paper>

            </div>
        );

    }
}

RegisterView.propTypes = {
    registerUser: React.PropTypes.func,
    registerStatusText: React.PropTypes.string,
};
