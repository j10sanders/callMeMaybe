const webpack = require('webpack');
const ExtractTextPlugin = require('extract-text-webpack-plugin');
require('dotenv').config();

module.exports = {
    devtool: 'source-map',

    entry: ['bootstrap-loader/extractStyles'],

    output: {
        publicPath: 'dist/',
    },

    module: {
        loaders: [{
            test: /\.scss$/,
            loader: 'style!css!postcss-loader!sass',
        }],
    },

    node: {
        fs: "empty"
    },

    stats: {
              colors: true,
              modules: true,
              reasons: true,
              errorDetails: true
            },

    plugins: [
        new webpack.DefinePlugin({
            'process.env': {
                NODE_ENV: '"production"',
                // REACT_APP_USERS_SERVICE_URL: 'http://localhost:5000',
            },
            __DEVELOPMENT__: false,
        }),
        new ExtractTextPlugin('bundle.css'),
        new webpack.optimize.DedupePlugin(),
        new webpack.optimize.OccurenceOrderPlugin(),
        new webpack.optimize.UglifyJsPlugin({
            compress: {
                warnings: false,
            },
        }),
    ],
};
