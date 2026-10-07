//! 可信 Probe state 根的唯一投影与退休机制。
//!
//! Uninstall 与 fresh 共用这份实现：public/private 两个固定投影的定位、整个根的内容
//! 清理和 empty-only 判定都封闭在这里。调用方只带已经成立的安装或恢复绑定，不传
//! child 名单、inode、phase 或形态开关。

use std::{
    fs::{self, File},
    io::{self, ErrorKind},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

/// canonical public 链必须精确携带的相对目标，同时给出固定 private 投影的位置。
const CANONICAL_PROJECTION: &str = "private/enoki-probe";

#[derive(Debug)]
pub enum ProbeStateRootError {
    /// 形态或归属不构成单一受支持投影；不取得任何删除权。
    Untrusted,
    /// 根仍携带本安装的实际 state 数据。
    HoldsData,
    Io(io::Error),
}

impl From<io::Error> for ProbeStateRootError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// 已定位的可信 state 根；内容根可能是 public 本体或固定 private 投影。
#[derive(Debug)]
pub struct ProbeStateRoot {
    form: ProbeStateRootForm,
}

#[derive(Debug)]
enum ProbeStateRootForm {
    Ordinary {
        public: PathBuf,
    },
    Canonical {
        public_link: Option<PathBuf>,
        private_root: Option<PathBuf>,
    },
}

impl ProbeStateRoot {
    /// 只解释固定两个投影。`Ok(None)` 表示 public 与 private 均 absent，即根已退休。
    pub fn resolve(public: &Path) -> Result<Option<Self>, ProbeStateRootError> {
        let private = public
            .parent()
            .ok_or(ProbeStateRootError::Untrusted)?
            .join(CANONICAL_PROJECTION);
        ensure_no_symlinked_ancestor(public)?;
        let public_entry = match entry(public)? {
            Some(entry) => entry,
            None => {
                return match entry(&private)? {
                    Some(private_entry) if is_dynamic_user_directory(&private_entry) => {
                        ensure_no_symlinked_ancestor(&private)?;
                        Ok(Some(Self {
                            form: ProbeStateRootForm::Canonical {
                                public_link: None,
                                private_root: Some(private),
                            },
                        }))
                    }
                    Some(_) => Err(ProbeStateRootError::Untrusted),
                    None => Ok(None),
                };
            }
        };
        let private_entry = entry(&private)?;
        if public_entry.file_type().is_symlink() {
            require_exact_public_link(public, &public_entry)?;
            match private_entry {
                Some(private_entry) if is_dynamic_user_directory(&private_entry) => {
                    ensure_no_symlinked_ancestor(&private)?;
                    Ok(Some(Self {
                        form: ProbeStateRootForm::Canonical {
                            public_link: Some(public.to_path_buf()),
                            private_root: Some(private),
                        },
                    }))
                }
                Some(_) => Err(ProbeStateRootError::Untrusted),
                None => Ok(Some(Self {
                    form: ProbeStateRootForm::Canonical {
                        public_link: Some(public.to_path_buf()),
                        private_root: None,
                    },
                })),
            }
        } else if private_entry.is_some() {
            Err(ProbeStateRootError::Untrusted)
        } else if is_root_install_directory(&public_entry) {
            Ok(Some(Self {
                form: ProbeStateRootForm::Ordinary {
                    public: public.to_path_buf(),
                },
            }))
        } else {
            Err(ProbeStateRootError::Untrusted)
        }
    }

    /// 受支持形态下枚举完毕后确实没有任何 child。canonical 独立检查固定 private，
    /// public absent 不掩盖 private 数据。
    pub fn is_proven_empty(&self) -> Result<bool, ProbeStateRootError> {
        let Some(content) = self.content_root() else {
            return Ok(true);
        };
        Ok(match fs::read_dir(content) {
            Ok(mut children) => children.next().is_none(),
            Err(error) if error.kind() == ErrorKind::NotFound => true,
            Err(error) => return Err(ProbeStateRootError::Io(error)),
        })
    }

    /// 有安装或恢复绑定的入口清空整个可信根内容；不跟随根内链接到外部。
    pub fn clear_authorized_contents(&self) -> Result<(), ProbeStateRootError> {
        let Some(content) = self.content_root() else {
            return Ok(());
        };
        remove_contents_no_follow(content)?;
        sync_directory(content)
    }

    /// 只在重新证明为空后尽力删除壳：canonical 先 private 再 exact public 链。
    /// 删除失败如实返回，由调用方按同一 empty 判据决定是否容许无害空壳。
    pub fn remove_empty_shell(&self) -> Result<(), ProbeStateRootError> {
        if !self.is_proven_empty()? {
            return Err(ProbeStateRootError::HoldsData);
        }
        match &self.form {
            ProbeStateRootForm::Ordinary { public } => remove_shell(public, false),
            ProbeStateRootForm::Canonical {
                public_link,
                private_root,
            } => {
                if let Some(private) = private_root {
                    remove_shell(private, false)?;
                }
                if let Some(link) = public_link {
                    remove_shell(link, true)?;
                }
                Ok(())
            }
        }
    }

    fn content_root(&self) -> Option<&Path> {
        match &self.form {
            ProbeStateRootForm::Ordinary { public } => Some(public),
            ProbeStateRootForm::Canonical { private_root, .. } => private_root.as_deref(),
        }
    }
}

fn entry(path: &Path) -> Result<Option<fs::Metadata>, ProbeStateRootError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(ProbeStateRootError::Io(error)),
    }
}

fn is_root_install_directory(metadata: &fs::Metadata) -> bool {
    !metadata.file_type().is_symlink()
        && metadata.is_dir()
        && metadata.uid() == 0
        && metadata.gid() == 0
}

fn is_dynamic_user_directory(metadata: &fs::Metadata) -> bool {
    !metadata.file_type().is_symlink() && metadata.is_dir() && metadata.uid() == metadata.gid()
}

fn require_exact_public_link(
    public: &Path,
    metadata: &fs::Metadata,
) -> Result<(), ProbeStateRootError> {
    if metadata.uid() != 0 || metadata.gid() != 0 {
        return Err(ProbeStateRootError::Untrusted);
    }
    match fs::read_link(public) {
        Ok(target) if target == Path::new(CANONICAL_PROJECTION) => Ok(()),
        Ok(_) | Err(_) => Err(ProbeStateRootError::Untrusted),
    }
}

/// 祖先只允许真实的目录。缺失祖先不取得删除权，也不掩盖随后的 absent 判定；真实的
/// symlink 或非目录祖先一律视为不可信，避免把删除权经由链接交给外部目标。
fn ensure_no_symlinked_ancestor(path: &Path) -> Result<(), ProbeStateRootError> {
    let mut current = path.parent();
    while let Some(directory) = current {
        match fs::symlink_metadata(directory) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(ProbeStateRootError::Untrusted);
                }
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(ProbeStateRootError::Io(error)),
        }
        current = directory.parent();
    }
    Ok(())
}

fn remove_contents_no_follow(path: &Path) -> Result<(), ProbeStateRootError> {
    for child in fs::read_dir(path)? {
        let child = child?;
        let metadata = fs::symlink_metadata(child.path())?;
        if metadata.is_dir() {
            remove_contents_no_follow(&child.path())?;
            remove_shell(&child.path(), false)?;
        } else {
            remove_shell(&child.path(), true)?;
        }
    }
    Ok(())
}

fn remove_shell(path: &Path, is_file: bool) -> Result<(), ProbeStateRootError> {
    let removed = if is_file {
        fs::remove_file(path)
    } else {
        fs::remove_dir(path)
    };
    match removed {
        Ok(()) => sync_parent(path),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(ProbeStateRootError::Io(error)),
    }
}

fn sync_directory(path: &Path) -> Result<(), ProbeStateRootError> {
    match File::open(path) {
        Ok(directory) => directory.sync_all()?,
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(ProbeStateRootError::Io(error)),
    }
    Ok(())
}

fn sync_parent(path: &Path) -> Result<(), ProbeStateRootError> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    sync_directory(parent)
}
