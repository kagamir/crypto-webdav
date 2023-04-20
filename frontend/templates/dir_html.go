package templates

const BrowserDirHtml = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Dir Browser</title>
</head>
<body>
<table style="border: 0">
    <tr>
        <th>Name</th>
        <th>Type</th>
        <th>Size</th>
        <th>Mode</th>
        <th>Last modified</th>
    </tr>
    {{range .Items}}
    <tr>
        <td><a href="{{.Path}}">{{.Name}}</a></td>
        <td>{{.IsDir}}</td>
        <td>{{.Size}}</td>
        <td>{{.Mode}}</td>
        <td>{{.ModTime}}</td>
    </tr>
    {{else}}
    <tr>
        <td>No items found.</td>
    </tr>
    {{end}}
</table>
</body>
</html>
`
