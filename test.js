const httpMethods = [
    'GET', 'HEAD', 'OPTIONS', 'TRACE',
    'PUT', 'DELETE', 'POST', 'PATCH',
    'CONNECT'
];

currentLine = 'GET';

console.log(httpMethods.includes(currentLine))