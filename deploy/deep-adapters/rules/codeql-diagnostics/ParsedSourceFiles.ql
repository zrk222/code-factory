/**
 * @name Parsed source files
 * @description Lists source files with extractor-recorded content type.
 * @kind diagnostic
 * @id factory/js/diagnostics/parsed-source-files
 */
import javascript

from File f
where exists(f.getRelativePath()) and exists(f.getFileType())
select f, ""
