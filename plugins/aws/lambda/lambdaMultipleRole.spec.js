var expect = require('chai').expect;
var lambdaMultipleRole = require('./lambdaMultipleRole');

const createCacheNoFunctions = () => {
    return {
        lambda: {
            listFunctions: {
                'us-east-1': {
                    data: []
                }
            }
        }
    };
};

const createCacheWithFunctions = (functions, roleArn) => {
    const getFunctionData = {};
    const getRoleData = {};
    functions.forEach(fn => {
        getFunctionData[fn] = {
            data: { Configuration: { Role: roleArn } }
        };
    });
    getRoleData[roleArn] = { data: { Role: {} } };

    return {
        lambda: {
            listFunctions: {
                'us-east-1': {
                    data: functions.map(fn => ({ FunctionName: fn }))
                }
            },
            getFunction: {
                'us-east-1': getFunctionData
            }
        },
        iam: {
            getRole: {
                'us-east-1': getRoleData
            }
        }
    };
};

const createCacheWithSharedRole = () => {
    return createCacheWithFunctions(['func1', 'func2'], 'arn:aws:iam::123:role/sharedRole');
};

const createCacheWithNoRole = () => {
    return {
        lambda: {
            listFunctions: {
                'us-east-1': {
                    data: [{ FunctionName: 'func1' }]
                }
            },
            getFunction: {
                'us-east-1': {
                    'func1': {
                        data: { Configuration: { Role: null } }
                    }
                }
            }
        }
    };
};

describe('lambdaMultipleRole Plugin', function () {
    describe('run', function () {
        it('should PASS if no Lambda functions found', function (done) {
            const cache = createCacheNoFunctions();
            lambdaMultipleRole.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Lambda functions found');
                done();
            });
        });

        it('should FAIL if IAM role is shared by multiple Lambda functions', function (done) {
            const cache = createCacheWithSharedRole();
            lambdaMultipleRole.run(cache, {}, (err, results) => {
                const fail = results.find(r => r.status === 2);
                expect(fail).to.not.be.undefined;
                expect(fail.message).to.include('shared by multiple Lambda functions');
                done();
            });
        });

        it('should PASS if IAM role is unique to a single Lambda function', function (done) {
            const cache = createCacheWithFunctions(['func1'], 'arn:aws:iam::123:role/uniqueRole');
            lambdaMultipleRole.run(cache, {}, (err, results) => {
                const pass = results.find(r => r.status === 0);
                expect(pass).to.not.be.undefined;
                expect(pass.message).to.include('uniquely assigned');
                done();
            });
        });

        it('should ERROR if Lambda has no IAM role', function (done) {
            const cache = createCacheWithNoRole();
            lambdaMultipleRole.run(cache, {}, (err, results) => {
                const error = results.find(r => r.status === 3);
                expect(error).to.not.be.undefined;
                expect(error.message).to.include('has NO assigned IAM role');
                done();
            });
        });
    });
});
