{
  "targets": [
    {
      "target_name": "node-wireguard",
      "sources": [
        "src/node-wireguard.cpp",
        "src/WireGuardClient.cpp",
        "src/netlink/NlSocket.cpp",
        "src/netlink/NlAttr.cpp",
        "src/netlink/RtLink.cpp",
        "src/helpers/IfName.cpp",
        "src/crypto/Key.cpp",
        "src/uapi/UapiSocket.cpp",
        "src/uapi/UapiCodec.cpp"
      ],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")",
        "<!@(pkg-config --cflags-only-I libmnl libcrypto | sed 's/-I//g')"
      ],
      "dependencies": [
        "<!(node -p \"require('node-addon-api').gyp\")"
      ],
      "cflags!": ["-fno-exceptions"],
      "cflags_cc!": ["-fno-exceptions"],
      "cflags_cc": ["-std=c++17"],
      "defines": ["NAPI_DISABLE_CPP_EXCEPTIONS"],
      "conditions": [
        [
          "OS=='linux'",
          {
            "libraries": [
              "<!@(pkg-config --libs libmnl libcrypto)"
            ]
          }
        ],
        [
          "OS!='linux'",
          {
            "type": "none"
          }
        ]
      ],
      "xcode_settings": {
        "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
        "CLANG_CXX_LIBRARY": "libc++",
        "MACOSX_DEPLOYMENT_TARGET": "10.7"
      },
      "msvs_settings": {
        "VCCLCompilerTool": {"ExceptionHandling": 1}
      }
    }
  ]
}
