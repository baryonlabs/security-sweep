const _ = require('lodash');
console.log(_.template('hi <%= x %>')({ x: 1 }));
