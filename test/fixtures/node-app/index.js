// Fixture: lodash is required (reachability should report "imported" or "called").
// minimist is in the lockfile but intentionally never required.
const _ = require('lodash');

const merged = _.merge({}, { a: 1 });
console.log(_.template('hello <%= name %>')({ name: 'world' }), merged);
