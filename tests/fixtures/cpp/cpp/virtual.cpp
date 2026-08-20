// Fixture for T-06-07: one virtual method, two overrides, one call site that
// cannot know which of them runs.
struct Codec {
    virtual int decode(int value);
    virtual ~Codec();
};

struct FastCodec : Codec {
    int decode(int value) override;
};

struct SafeCodec : Codec {
    int decode(int value) override;
};

int Codec::decode(int value)
{
    return value;
}

Codec::~Codec() = default;

int FastCodec::decode(int value)
{
    return value * 2;
}

int SafeCodec::decode(int value)
{
    return value > 0 ? value : 0;
}

int run(Codec *codec, int value)
{
    return codec->decode(value);
}
