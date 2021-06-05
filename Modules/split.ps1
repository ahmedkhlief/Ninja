
#taken from https://gist.github.com/jehugaleahsa

function split($path, $chunkSize=307374182)
{
    $fileName = [System.IO.Path]::GetFileNameWithoutExtension($path)
    $directory = [System.IO.Path]::GetDirectoryName($path)
    $extension = [System.IO.Path]::GetExtension($path)

    $file = New-Object System.IO.FileInfo($path)
    $totalChunks = [int]($file.Length / $chunkSize) + 1
    $digitCount = [int][System.Math]::Log10($totalChunks) + 1

    $reader = [System.IO.File]::OpenRead($path)
    $count = 0
    $buffer = New-Object Byte[] $chunkSize
    $hasMore = $true
    while($hasMore)
    {
        $bytesRead = $reader.Read($buffer, 0, $buffer.Length)
        $chunkFileName = "$directory\$fileName$extension.{0:D$digitCount}.part"
        $chunkFileName = $chunkFileName -f $count
        $output = $buffer
        if ($bytesRead -ne $buffer.Length)
        {
            $hasMore = $false
            $output = New-Object Byte[] $bytesRead
            [System.Array]::Copy($buffer, $output, $bytesRead)
        }
        [System.IO.File]::WriteAllBytes($chunkFileName, $output)
        ++$count
    }

    $reader.Close()
}
