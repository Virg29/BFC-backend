"""empty message

Revision ID: 1295913cd213
Revises: 1d0c602a46f1
Create Date: 2019-12-15 09:01:43.234050

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '1295913cd213'
down_revision = '1d0c602a46f1'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('tag',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('tag', sa.String(length=150), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('tag')
    # ### end Alembic commands ###
