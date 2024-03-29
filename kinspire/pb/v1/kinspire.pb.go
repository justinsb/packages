// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        (unknown)
// source: api/v1/kinspire.proto

package v1

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type GetExternalAuthRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Target string `protobuf:"bytes,1,opt,name=target,proto3" json:"target,omitempty"`
}

func (x *GetExternalAuthRequest) Reset() {
	*x = GetExternalAuthRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_v1_kinspire_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetExternalAuthRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetExternalAuthRequest) ProtoMessage() {}

func (x *GetExternalAuthRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1_kinspire_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetExternalAuthRequest.ProtoReflect.Descriptor instead.
func (*GetExternalAuthRequest) Descriptor() ([]byte, []int) {
	return file_api_v1_kinspire_proto_rawDescGZIP(), []int{0}
}

func (x *GetExternalAuthRequest) GetTarget() string {
	if x != nil {
		return x.Target
	}
	return ""
}

type GetExternalAuthReply struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AwsAuth *AWSAuthentication `protobuf:"bytes,1,opt,name=aws_auth,json=awsAuth,proto3" json:"aws_auth,omitempty"`
}

func (x *GetExternalAuthReply) Reset() {
	*x = GetExternalAuthReply{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_v1_kinspire_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetExternalAuthReply) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetExternalAuthReply) ProtoMessage() {}

func (x *GetExternalAuthReply) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1_kinspire_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetExternalAuthReply.ProtoReflect.Descriptor instead.
func (*GetExternalAuthReply) Descriptor() ([]byte, []int) {
	return file_api_v1_kinspire_proto_rawDescGZIP(), []int{1}
}

func (x *GetExternalAuthReply) GetAwsAuth() *AWSAuthentication {
	if x != nil {
		return x.AwsAuth
	}
	return nil
}

type AWSAuthentication struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AccessKeyId     string                 `protobuf:"bytes,1,opt,name=access_key_id,json=accessKeyId,proto3" json:"access_key_id,omitempty"`
	SecretAccessKey string                 `protobuf:"bytes,2,opt,name=secret_access_key,json=secretAccessKey,proto3" json:"secret_access_key,omitempty"`
	SessionToken    string                 `protobuf:"bytes,3,opt,name=session_token,json=sessionToken,proto3" json:"session_token,omitempty"`
	ExpirationTime  *timestamppb.Timestamp `protobuf:"bytes,4,opt,name=expiration_time,json=expirationTime,proto3" json:"expiration_time,omitempty"`
}

func (x *AWSAuthentication) Reset() {
	*x = AWSAuthentication{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_v1_kinspire_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AWSAuthentication) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AWSAuthentication) ProtoMessage() {}

func (x *AWSAuthentication) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1_kinspire_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AWSAuthentication.ProtoReflect.Descriptor instead.
func (*AWSAuthentication) Descriptor() ([]byte, []int) {
	return file_api_v1_kinspire_proto_rawDescGZIP(), []int{2}
}

func (x *AWSAuthentication) GetAccessKeyId() string {
	if x != nil {
		return x.AccessKeyId
	}
	return ""
}

func (x *AWSAuthentication) GetSecretAccessKey() string {
	if x != nil {
		return x.SecretAccessKey
	}
	return ""
}

func (x *AWSAuthentication) GetSessionToken() string {
	if x != nil {
		return x.SessionToken
	}
	return ""
}

func (x *AWSAuthentication) GetExpirationTime() *timestamppb.Timestamp {
	if x != nil {
		return x.ExpirationTime
	}
	return nil
}

var File_api_v1_kinspire_proto protoreflect.FileDescriptor

var file_api_v1_kinspire_proto_rawDesc = []byte{
	0x0a, 0x15, 0x61, 0x70, 0x69, 0x2f, 0x76, 0x31, 0x2f, 0x6b, 0x69, 0x6e, 0x73, 0x70, 0x69, 0x72,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x09, 0x62, 0x6c, 0x6f, 0x62, 0x73, 0x74, 0x6f,
	0x72, 0x65, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x22, 0x30, 0x0a, 0x16, 0x47, 0x65, 0x74, 0x45, 0x78, 0x74, 0x65, 0x72, 0x6e,
	0x61, 0x6c, 0x41, 0x75, 0x74, 0x68, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x16, 0x0a,
	0x06, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x74,
	0x61, 0x72, 0x67, 0x65, 0x74, 0x22, 0x4f, 0x0a, 0x14, 0x47, 0x65, 0x74, 0x45, 0x78, 0x74, 0x65,
	0x72, 0x6e, 0x61, 0x6c, 0x41, 0x75, 0x74, 0x68, 0x52, 0x65, 0x70, 0x6c, 0x79, 0x12, 0x37, 0x0a,
	0x08, 0x61, 0x77, 0x73, 0x5f, 0x61, 0x75, 0x74, 0x68, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x1c, 0x2e, 0x62, 0x6c, 0x6f, 0x62, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x41, 0x57, 0x53, 0x41,
	0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x07, 0x61,
	0x77, 0x73, 0x41, 0x75, 0x74, 0x68, 0x22, 0xcd, 0x01, 0x0a, 0x11, 0x41, 0x57, 0x53, 0x41, 0x75,
	0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x22, 0x0a, 0x0d,
	0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x0b, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4b, 0x65, 0x79, 0x49, 0x64,
	0x12, 0x2a, 0x0a, 0x11, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x5f, 0x61, 0x63, 0x63, 0x65, 0x73,
	0x73, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0f, 0x73, 0x65, 0x63,
	0x72, 0x65, 0x74, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4b, 0x65, 0x79, 0x12, 0x23, 0x0a, 0x0d,
	0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x0c, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x54, 0x6f, 0x6b, 0x65,
	0x6e, 0x12, 0x43, 0x0a, 0x0f, 0x65, 0x78, 0x70, 0x69, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f,
	0x74, 0x69, 0x6d, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d,
	0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0e, 0x65, 0x78, 0x70, 0x69, 0x72, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x32, 0x63, 0x0a, 0x08, 0x4b, 0x69, 0x6e, 0x73, 0x70, 0x69,
	0x72, 0x65, 0x12, 0x57, 0x0a, 0x0f, 0x47, 0x65, 0x74, 0x45, 0x78, 0x74, 0x65, 0x72, 0x6e, 0x61,
	0x6c, 0x41, 0x75, 0x74, 0x68, 0x12, 0x21, 0x2e, 0x62, 0x6c, 0x6f, 0x62, 0x73, 0x74, 0x6f, 0x72,
	0x65, 0x2e, 0x47, 0x65, 0x74, 0x45, 0x78, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x41, 0x75, 0x74,
	0x68, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1f, 0x2e, 0x62, 0x6c, 0x6f, 0x62, 0x73,
	0x74, 0x6f, 0x72, 0x65, 0x2e, 0x47, 0x65, 0x74, 0x45, 0x78, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c,
	0x41, 0x75, 0x74, 0x68, 0x52, 0x65, 0x70, 0x6c, 0x79, 0x22, 0x00, 0x42, 0x90, 0x01, 0x0a, 0x0d,
	0x63, 0x6f, 0x6d, 0x2e, 0x62, 0x6c, 0x6f, 0x62, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x42, 0x0d, 0x4b,
	0x69, 0x6e, 0x73, 0x70, 0x69, 0x72, 0x65, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x2c,
	0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6a, 0x75, 0x73, 0x74, 0x69,
	0x6e, 0x73, 0x62, 0x2f, 0x70, 0x61, 0x63, 0x6b, 0x61, 0x67, 0x65, 0x73, 0x2f, 0x6b, 0x69, 0x6e,
	0x73, 0x70, 0x69, 0x72, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x76, 0x31, 0xa2, 0x02, 0x03, 0x42,
	0x58, 0x58, 0xaa, 0x02, 0x09, 0x42, 0x6c, 0x6f, 0x62, 0x73, 0x74, 0x6f, 0x72, 0x65, 0xca, 0x02,
	0x09, 0x42, 0x6c, 0x6f, 0x62, 0x73, 0x74, 0x6f, 0x72, 0x65, 0xe2, 0x02, 0x15, 0x42, 0x6c, 0x6f,
	0x62, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x5c, 0x47, 0x50, 0x42, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61,
	0x74, 0x61, 0xea, 0x02, 0x09, 0x42, 0x6c, 0x6f, 0x62, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_api_v1_kinspire_proto_rawDescOnce sync.Once
	file_api_v1_kinspire_proto_rawDescData = file_api_v1_kinspire_proto_rawDesc
)

func file_api_v1_kinspire_proto_rawDescGZIP() []byte {
	file_api_v1_kinspire_proto_rawDescOnce.Do(func() {
		file_api_v1_kinspire_proto_rawDescData = protoimpl.X.CompressGZIP(file_api_v1_kinspire_proto_rawDescData)
	})
	return file_api_v1_kinspire_proto_rawDescData
}

var file_api_v1_kinspire_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_api_v1_kinspire_proto_goTypes = []interface{}{
	(*GetExternalAuthRequest)(nil), // 0: blobstore.GetExternalAuthRequest
	(*GetExternalAuthReply)(nil),   // 1: blobstore.GetExternalAuthReply
	(*AWSAuthentication)(nil),      // 2: blobstore.AWSAuthentication
	(*timestamppb.Timestamp)(nil),  // 3: google.protobuf.Timestamp
}
var file_api_v1_kinspire_proto_depIdxs = []int32{
	2, // 0: blobstore.GetExternalAuthReply.aws_auth:type_name -> blobstore.AWSAuthentication
	3, // 1: blobstore.AWSAuthentication.expiration_time:type_name -> google.protobuf.Timestamp
	0, // 2: blobstore.Kinspire.GetExternalAuth:input_type -> blobstore.GetExternalAuthRequest
	1, // 3: blobstore.Kinspire.GetExternalAuth:output_type -> blobstore.GetExternalAuthReply
	3, // [3:4] is the sub-list for method output_type
	2, // [2:3] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_api_v1_kinspire_proto_init() }
func file_api_v1_kinspire_proto_init() {
	if File_api_v1_kinspire_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_api_v1_kinspire_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetExternalAuthRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_v1_kinspire_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetExternalAuthReply); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_v1_kinspire_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AWSAuthentication); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_api_v1_kinspire_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_api_v1_kinspire_proto_goTypes,
		DependencyIndexes: file_api_v1_kinspire_proto_depIdxs,
		MessageInfos:      file_api_v1_kinspire_proto_msgTypes,
	}.Build()
	File_api_v1_kinspire_proto = out.File
	file_api_v1_kinspire_proto_rawDesc = nil
	file_api_v1_kinspire_proto_goTypes = nil
	file_api_v1_kinspire_proto_depIdxs = nil
}
