const expect = require('chai').expect;
const lambdaPlugin = require('./lambdaMissingExecutionRole'); // Make sure the path is correct
const helpers = require('../../../helpers/aws');

// Sample Lambda functions
const listFunctions = [
    {
        FunctionName: "lambda-with-role",
        FunctionArn: "arn:aws:lambda:us-east-1:000011112222:function:lambda-with-role",
        Role: "arn:aws:iam::000011112222:role/ExistingRole"
    },
    {
        FunctionName: "lambda-missing-role",
        FunctionArn: "arn:aws:lambda:us-east-1:000011112222:function:lambda-missing-role",
        Role: "arn:aws:iam::000011112222:role/MissingRole"
    },
    {
        FunctionArn: "arn:aws:lambda:us-east-1:000011112222:function:lambda-no-name",
        Role: "arn:aws:iam::000011112222:role/ExistingRole"
    }
];

// Mock helpers.addSource
helpers.addSource = function(cache, source, path) {
    const [service, action, region, name] = path;

    if (service === 'lambda' && action === 'listFunctions') {
        return cache.lambda.listFunctionsFail
            ? { err: 'Unable to list Lambda functions', data: null }
            : { err: null, data: cache.lambda.listFunctions[region] || [] };
    }

    if (service === 'lambda' && action === 'getFunction') {
        if (cache.lambda.getFunctionFail) return { err: 'Unable to get Lambda function', data: null };
        const fn = cache.lambda.listFunctions[region].find(f => f.FunctionName === name);
        return fn ? { data: { Configuration: fn } } : { err: 'Function not found' };
    }

    if (service === 'iam' && action === 'listRoles') {
        return cache.iam.listRolesFail
            ? { err: 'Unable to list IAM roles', data: null }
            : { err: null, data: cache.iam.listRoles[region] || [] };
    }

    if (service === 'iam' && action === 'getRole') {
        if (cache.iam.getRoleFail) return { err: 'Unable to get IAM role', data: null };
        const role = cache.iam.listRoles[region].find(r => r.RoleName === name);
        return role ? { data: { Role: role } } : { err: 'Role not found', data: null };
    }

    return null;
};

// Mock regions function to only use 'us-east-1'
helpers.regions = function(settings) {
    return { lambda: ['us-east-1'], iam: ['us-east-1'] };
};

describe('Lambda Execution Role Plugin Tests', function () {

    it('1. No Lambda functions found -> Pass', function(done) {
        const cache = {
            lambda: { listFunctions: { 'us-east-1': [] } },
            iam: { listRoles: { 'us-east-1': [{ RoleName: 'ExistingRole' }] } }
        };
        lambdaPlugin.run(cache, {}, function(err, results) {
            expect(results.every(r => r.status === 0)).to.be.true;
            done();
        });
    });

    it('2. Cannot get Lambda functions -> Fail', function(done) {
        const cache = {
            lambda: { listFunctionsFail: true },
            iam: { listRoles: { 'us-east-1': [{ RoleName: 'ExistingRole' }] } }
        };
        lambdaPlugin.run(cache, {}, function(err, results) {
            expect(results.some(r => r.status === 3)).to.be.true;
            done();
        });
    });

    it('3. Cannot get IAM roles -> Fail', function(done) {
        const cache = {
            lambda: { listFunctions: { 'us-east-1': [listFunctions[0]] } },
            iam: { listRolesFail: true }
        };
        lambdaPlugin.run(cache, {}, function(err, results) {
            expect(results.some(r => r.status === 3)).to.be.true;
            done();
        });
    });

    it('4. Cannot get details of Lambda function -> Fail', function(done) {
        const cache = {
            lambda: { listFunctions: { 'us-east-1': [listFunctions[0]] }, getFunctionFail: true },
            iam: { listRoles: { 'us-east-1': [{ RoleName: 'ExistingRole' }] } }
        };
        lambdaPlugin.run(cache, {}, function(err, results) {
            expect(results.some(r => r.status === 3)).to.be.true;
            done();
        });
    });

    it('5. Lambda function has no assigned role -> Fail', function(done) {
        const lambdaNoRole = { ...listFunctions[0], Role: null };
        const cache = {
            lambda: { listFunctions: { 'us-east-1': [lambdaNoRole] } },
            iam: { listRoles: { 'us-east-1': [{ RoleName: 'ExistingRole' }] } }
        };
        lambdaPlugin.run(cache, {}, function(err, results) {
            expect(results.some(r => r.status === 3)).to.be.true;
            done();
        });
    });

    it('6. Lambda function has valid role -> Pass', function(done) {
        const cache = {
            lambda: { listFunctions: { 'us-east-1': [listFunctions[0]] } },
            iam: { listRoles: { 'us-east-1': [{ RoleName: 'ExistingRole' }] } }
        };
        lambdaPlugin.run(cache, {}, function(err, results) {
            expect(results.every(r => r.status === 0)).to.be.true;
            done();
        });
    });

    it('7. Lambda function role not found in IAM -> Fail', function(done) {
        const cache = {
            lambda: { listFunctions: { 'us-east-1': [listFunctions[1]] } },
            iam: { listRoles: { 'us-east-1': [{ RoleName: 'SomeOtherRole' }] } }
        };
        lambdaPlugin.run(cache, {}, function(err, results) {
            expect(results.some(r => r.status === 2)).to.be.true;
            done();
        });
    });

    it('8. Cannot get details of assigned role -> Warning', function(done) {
        const cache = {
            lambda: { listFunctions: { 'us-east-1': [listFunctions[0]] } },
            iam: { 
                listRoles: { 'us-east-1': [{ RoleName: 'ExistingRole' }] },
                getRoleFail: true
            }
        };
        lambdaPlugin.run(cache, {}, function(err, results) {
            expect(results.some(r => r.status === 2)).to.be.true;
            done();
        });
    });

});
