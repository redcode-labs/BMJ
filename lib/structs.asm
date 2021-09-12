struc STAT
    .st_dev         resq 1
    .st_ino         resq 1
    .st_nlink       resq 1
    .st_mode        resd 1
    .st_uid         resd 1
    .st_gid         resd 1
    .pad0           resb 4
    .st_rdev        resq 1
    .st_size        resq 1
    .st_blksize     resq 1
    .st_blocks      resq 1
    .st_atime       resq 1
    .st_atime_nsec  resq 1
    .st_mtime       resq 1
    .st_mtime_nsec  resq 1
    .st_ctime       resq 1
    .st_ctime_nsec  resq 1
endstruc

struc STATX
	.stx_mask resd 1
	.stx_bulksize resd 1
	.stx_attributes resq 1
	.stx_nlink resd 1
	.stx_uid resd 1
	.stx_gid resd 1
	.stx_mode resw 1
	.stx_ino resq 1
	.stx_size resq 1
	.stx_blocks resq 1
	.stx_attributes_mask resq 1
    .st_atime       resq 1
    .st_atime_nsec  resq 1
    .st_btime       resq 1
    .st_btime_nsec  resq 1
    .st_ctime       resq 1
    .st_ctime_nsec  resq 1
    .st_mtime       resq 1
    .st_mtime_nsec  resq 1
endstruc

struc TYPES 
	.long: resd 1
	.word: resw 1
	.byte: resb 1
endstruc

struc TIMESPEC 
	.sec: resd 1
	.nsec: resd 1
endstruc