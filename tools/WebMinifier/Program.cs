/*
ZenitiumDNS
Copyright (C) 2026  xRuffKez

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

using NUglify;
using NUglify.Css;
using NUglify.Html;
using NUglify.JavaScript;
using System;
using System.IO;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace WebMinifier
{
    static partial class Program
    {
        static readonly UTF8Encoding _utf8 = new UTF8Encoding(false);

        static long _before;
        static long _after;
        static int _files;

        [GeneratedRegex(@"^\s*(//[#@] sourceMappingURL=\S+|/\*[#@] sourceMappingURL=\S+ \*/)\s*$", RegexOptions.Multiline)]
        private static partial Regex SourceMapRegex();

        static CodeSettings GetJsSettings()
        {
            return new CodeSettings()
            {
                LocalRenaming = LocalRenaming.CrunchAll,
                PreserveFunctionNames = true,
                RemoveUnneededCode = false,
                PreserveImportantComments = false,
                EvalTreatment = EvalTreatment.MakeImmediateSafe,
                TermSemicolons = true
            };
        }

        static CssSettings GetCssSettings()
        {
            return new CssSettings()
            {
                CommentMode = CssComment.None
            };
        }

        static HtmlSettings GetHtmlSettings()
        {
            HtmlSettings settings = new HtmlSettings()
            {
                RemoveComments = true,
                CollapseWhitespaces = true,
                KeepOneSpaceWhenCollapsing = true,
                RemoveOptionalTags = false,
                RemoveAttributeQuotes = false,
                RemoveEmptyAttributes = false,
                RemoveScriptStyleTypeAttribute = false,
                DecodeEntityCharacters = false,
                ShortBooleanAttribute = false,
                MinifyJs = true,
                MinifyJsAttributes = false,
                MinifyCss = true,
                MinifyCssAttributes = false,
                AttributesCaseSensitive = true,
                IsFragmentOnly = false
            };

            settings.JsSettings = GetJsSettings();
            settings.CssSettings = GetCssSettings();

            return settings;
        }

        static string Check(UglifyResult result, string file)
        {
            if (result.HasErrors)
            {
                StringBuilder sb = new StringBuilder();

                foreach (UglifyError error in result.Errors)
                {
                    if (error.IsError)
                        sb.AppendLine(file + "(" + error.StartLine + "," + error.StartColumn + "): " + error.Message);
                }

                if (sb.Length > 0)
                    throw new InvalidDataException(sb.ToString());
            }

            return result.Code;
        }

        static string MinifyJson(string text)
        {
            using (JsonDocument document = JsonDocument.Parse(text))
            {
                using (MemoryStream mS = new MemoryStream())
                {
                    using (Utf8JsonWriter writer = new Utf8JsonWriter(mS, new JsonWriterOptions() { Indented = false, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping }))
                    {
                        document.WriteTo(writer);
                    }

                    return _utf8.GetString(mS.ToArray());
                }
            }
        }

        static void ProcessFile(string file)
        {
            string name = Path.GetFileName(file);
            string extension = Path.GetExtension(file).ToLowerInvariant();

            if (extension == ".map")
            {
                _before += new FileInfo(file).Length;
                File.Delete(file);
                _files++;
                return;
            }

            string text;
            bool minified = name.EndsWith(".min.js", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".min.css", StringComparison.OrdinalIgnoreCase);

            switch (extension)
            {
                case ".js":
                case ".css":
                case ".html":
                case ".htm":
                case ".json":
                    text = File.ReadAllText(file);
                    break;

                default:
                    return;
            }

            string output;

            if (minified)
                output = SourceMapRegex().Replace(text, "").TrimEnd() + "\n";
            else if (extension == ".js")
                output = Check(Uglify.Js(text, file, GetJsSettings()), file);
            else if (extension == ".css")
                output = Check(Uglify.Css(text, file, GetCssSettings()), file);
            else if (extension == ".json")
                output = MinifyJson(text);
            else
                output = Check(Uglify.Html(text, GetHtmlSettings(), file), file);

            byte[] before = File.ReadAllBytes(file);
            byte[] after = _utf8.GetBytes(output);

            _before += before.Length;
            _after += after.Length;
            _files++;

            File.WriteAllBytes(file, after);
        }

        static int Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.Error.WriteLine("Usage: WebMinifier <folder> [<folder> ...]");
                return 2;
            }

            try
            {
                foreach (string folder in args)
                {
                    if (!Directory.Exists(folder))
                        throw new DirectoryNotFoundException("Folder not found: " + folder);

                    foreach (string file in Directory.GetFiles(folder, "*", SearchOption.AllDirectories))
                        ProcessFile(file);
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("WebMinifier failed: " + ex.Message);
                return 1;
            }

            Console.WriteLine("WebMinifier: " + _files + " files, " + (_before / 1024) + " KB -> " + (_after / 1024) + " KB");
            return 0;
        }
    }
}
